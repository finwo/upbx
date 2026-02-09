#ifndef UPBX_RTP_RELAY_H
#define UPBX_RTP_RELAY_H

#include <stddef.h>
#include <sys/select.h>
#include <netinet/in.h>

struct upbx_config;

/* RTP direction: whose media we're receiving on this leg */
#define RTP_RELAY_DIR_INCOMING  0  /* RTP from remote (offerer/answerer) toward us */
#define RTP_RELAY_DIR_OUTGOING  1  /* RTP from the other party toward us */

/* Call direction: incoming call (DID→ext) or outgoing (ext→trunk) */
#define RTP_RELAY_CALL_INCOMING  0
#define RTP_RELAY_CALL_OUTGOING  1

/* Initialize built-in RTP relay (port range, table). Uses cfg->rtp_port_low/high.
 * Call once at startup. Returns 0 on success, -1 on error. */
int rtp_relay_init(struct upbx_config *cfg);

/* Add all active RTP/RTCP socket fds to the set for select(). */
void rtp_relay_fill_fds(fd_set *read_set, int *maxfd);

/* For each fd in read_set that is an RTP relay socket, read and forward. Call after select(). */
void rtp_relay_poll(fd_set *read_set);

/* Start one RTP relay leg. local_ip: we bind to this (e.g. INADDR_ANY).
 * remote_ip/remote_port: the UA we're receiving from / sending to.
 * On success, *local_port is set to our bound port (even; RTP; RTP+1 is RTCP).
 * call_id_number and call_id_host identify the call (from SIP Call-ID).
 * Returns 0 on success, -1 on error. */
int rtp_relay_start_fwd(struct upbx_config *cfg,
  const char *call_id_number, const char *call_id_host,
  int rtp_direction, int call_direction, int media_stream_no,
  struct in_addr local_ip, int *local_port,
  struct in_addr remote_ip, int remote_port,
  int cseq);

/* Stop RTP relay leg(s). If media_stream_no < 0, stop all media for this call+direction.
 * If cseq >= 0, only stop if stored cseq <= cseq. */
int rtp_relay_stop_fwd(const char *call_id_number, const char *call_id_host,
  int rtp_direction, int media_stream_no, int cseq);

#endif
