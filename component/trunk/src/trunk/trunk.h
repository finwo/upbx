#ifndef TRK_TRUNK_H
#define TRK_TRUNK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include "config/config.h"
#include "rtp/rtp.h"
#include "finwo/scheduler.h"

enum call_state {
    CALL_WAITING,
    CALL_RINGING,
    CALL_ACTIVE,
    CALL_ENDED,
};

enum call_direction {
    CALL_INCOMING,    // trunk → backbone (SIP INVITE from trunk)
    CALL_OUTGOING,    // backbone → trunk (backbone invite filtered in)
};

struct trunk_call {
    char *sip_call_id;
    char backbone_call_id[33];
    enum call_direction direction;
    enum call_state state;

    /* SIP dialog state */
    struct sockaddr_storage trunk_addr;
    int trunk_fd;
    char *trunk_did;
    char *trunk_cid;
    int cseq_num;
    char branch[32];           /* Via branch parameter for this call */
    char from_tag[32];         /* From tag for this call */

    /* Dialog headers for response building */
    char *trunk_via;
    char *trunk_from;
    char *trunk_to;
    char *trunk_contact;
    char gw_tag[16];

    /* RTP */
    struct rtp_pair *rtp;

    /* Remote SDP info from trunk provider */
    char *remote_sdp_host;
    int remote_sdp_port;

    /* Diagnostics */
    int media_logged;

    /* Delay timer for outgoing calls */
    int delay_active;
    int64_t delay_started;

    /* Tags from backbone invite (outgoing direction) */
    char *backbone_tags;

    struct trunk_call *next;
};

struct trunk_state {
    struct trk_config *config;
    struct backbone_state *backbone;
    int *sip_fds;
    char listen_addr[INET6_ADDRSTRLEN]; // auto-detected local IP for SDP/SIP

    /* Resolved target address — set once at startup */
    struct sockaddr_storage target_addr; // upstream address (resolved)
    socklen_t target_addrlen;            // sizeof(sockaddr_in) or sockaddr_in6
    int target_af;                       // AF_INET or AF_INET6

    /* Registration state (owned by sip recv task) */
    int reg_registered;
    int64_t reg_last_send;
    int reg_expires;

    /* NAT keepalive state */
    int64_t keepalive_last_send;

    /* NAT-detected public address (from Via received/rport in REGISTER response) */
    char public_addr[INET6_ADDRSTRLEN];
    int  public_port;

    struct rtp_alloc_ctx rtp_ctx;
    struct trunk_call *calls;
    pt_task_t *sip_task;
    pt_task_t *delay_task;
};

struct trunk_state *trunk_create(struct trk_config *cfg);
void trunk_free(struct trunk_state *ts);

/* Scheduler tasks */
int trunk_sip_recv_task(int64_t ts, struct pt_task *pt);
int trunk_delay_task(int64_t ts, struct pt_task *pt);

/* Called by backbone module when it receives protocol lines */
void trunk_handle_backbone_invite(struct trunk_state *ts, const char *call_id,
                                  const char *did, const char *cid,
                                  const char *tags_str);

/* Backbone event callbacks */
void trunk_on_backbone_ringing(struct trunk_state *s, const char *call_id, const char *codec_tags);
void trunk_on_backbone_answer(struct trunk_state *s, const char *call_id, const char *codec_tags);
void trunk_on_backbone_cancel(struct trunk_state *s, const char *call_id);
void trunk_on_backbone_media(struct trunk_state *s, const char *call_id, int stream_id,
                             const uint8_t *data, size_t len);
void trunk_on_backbone_bye(struct trunk_state *s, const char *call_id);

/* Call lookup */
struct trunk_call *trunk_find_by_sip_id(struct trunk_state *s, const char *sip_call_id);
struct trunk_call *trunk_find_by_backbone_id(struct trunk_state *s, const char *bb_call_id);

#endif
