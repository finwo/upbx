#ifndef UPBX_CALL_H
#define UPBX_CALL_H

#include <stddef.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "config.h"

/* Maximum Call-ID length we store. */
#define CALL_ID_MAX 256

/* One party in a call (caller or callee). */
typedef struct {
  struct sockaddr_storage sip_addr;   /* SIP signaling address            */
  socklen_t              sip_len;
  char                  *id;          /* extension number or trunk name   */
  char                  *tag;         /* From-tag (party A) or To-tag (B) */
} call_party_t;

/* Unified call state: SIP session + RTP relay. */
typedef struct call {
  struct call *next;
  char         call_id[CALL_ID_MAX];

  call_party_t a;                     /* caller  (sent the INVITE to us)  */
  call_party_t b;                     /* callee  (set from 200 OK)        */

  /* Forking: SIP addresses we sent INVITE to (for ACK/CANCEL). */
  #define CALL_MAX_FORKS 8
  #define FORK_ACTIVE  0    /* INVITE sent, waiting for response          */
  #define FORK_DONE    1    /* Final non-2xx received (not retryable)     */
  #define FORK_BUSY    2    /* 486 Busy received, waiting for retry       */
  struct sockaddr_storage fork_addrs[CALL_MAX_FORKS];
  socklen_t              fork_lens[CALL_MAX_FORKS];
  char                  *fork_ids[CALL_MAX_FORKS];
  char                  *fork_vias[CALL_MAX_FORKS]; /* Via value we used (for CANCEL) */
  int                    fork_state[CALL_MAX_FORKS]; /* FORK_ACTIVE/DONE/BUSY */
  size_t                 n_forks;

  /* Extensions pending (re-)INVITE: initially populated by fork setup,
   * repopulated when a fork responds 486 Busy. The pending handler in
   * overflow_pt drains this list by sending INVITEs when extensions are free. */
  char                  *pending_exts[CALL_MAX_FORKS];
  size_t                 n_pending_exts;

  /* RTP relay: one socket facing each party.
   * Receive on rtp_sock_a → sendto(rtp_remote_b)
   * Receive on rtp_sock_b → sendto(rtp_remote_a) */
  int                rtp_sock_a;      /* bound UDP socket facing party A  */
  int                rtp_port_a;      /* local even port for party A      */
  struct sockaddr_in rtp_remote_a;    /* where party A expects RTP        */

  int                rtp_sock_b;      /* bound UDP socket facing party B  */
  int                rtp_port_b;      /* local even port for party B      */
  struct sockaddr_in rtp_remote_b;    /* where party B expects RTP        */

  /* SIP state */
  int           sockfd;               /* UDP socket used for SIP sending  */
  int           answered;
  int           cancelling;            /* CANCEL sent to forks, awaiting 487 */
  time_t        created_at;
  time_t        answered_at;
  time_t        rtp_active_at;        /* last RTP forwarded (for aging)   */
  unsigned long rtp_pkts_a2b;         /* packets relayed caller→callee    */
  unsigned long rtp_pkts_b2a;         /* packets relayed callee→caller    */
  time_t        rtp_log_at;           /* last time we logged RTP stats    */

  char         *original_invite;      /* stored for ACK/BYE generation    */
  size_t        original_invite_len;
  char         *caller_via;           /* caller's first Via (restored on responses) */

  /* Routing / plugin metadata */
  config_trunk *trunk;                /* NULL for ext-to-ext              */
  char         *source_str;           /* caller id (for plugins)          */
  char         *dest_str;             /* callee id (for plugins)          */
  char         *direction;            /* "dialin" or "dialout" (for CALL.ANSWER/HANGUP events) */
  int           overflow_done;
} call_t;

/* Pre-remove callback (for plugin notifications) */

/* Called before a call is removed from the list. Set once at startup. */
typedef void (*call_pre_remove_cb)(call_t *call);
void call_set_pre_remove_callback(call_pre_remove_cb cb);

/* Lifecycle */

/* Allocate a new call, set call_id and created_at. Returns NULL on failure. */
call_t *call_create(const char *call_id);

/* Find a call by Call-ID. Returns NULL if not found. */
call_t *call_find(const char *call_id);

/* Remove a call: close RTP sockets, free strings, unlink from list. */
void call_remove(call_t *call);

/* Return the head of the call list (for iteration). */
call_t *call_first(void);

/* RTP port allocation */

/* Bind an even UDP port from the configured range.
 * On success, sets *sock and *port. Returns 0 on success, -1 on failure. */
int call_rtp_alloc_port(struct in_addr local_ip, int port_low, int port_high,
                        int *sock, int *port);

/* select() integration */

/* Add all active RTP sockets to the fd_set for select(). */
void call_fill_rtp_fds(fd_set *read_set, int *maxfd);

/* For each readable RTP socket, forward to the opposite party. */
void call_relay_rtp(fd_set *read_set);

/* Remove calls with no RTP activity for more than timeout_sec. */
void call_age_idle(int timeout_sec);

#endif
