#ifndef GW_PBX_H
#define GW_PBX_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "config/config.h"
#include "rtp/rtp.h"
#include "finwo/scheduler.h"

/* Make sure pt_task_t is available for task function signatures */
#ifndef GW_SCHEDULER_INCLUDED
#define GW_SCHEDULER_INCLUDED
#endif

enum call_state {
    CALL_PENDING,
    CALL_RINGING,
    CALL_ACTIVE,
    CALL_ENDED,
};

struct fork_branch {
    struct gw_ext *ext;
    char *sip_call_id;
    struct sockaddr_storage addr;
    struct rtp_pair *rtp;
    int answered;
    int busy;
    time_t retry_at;
    int invite_sent;
    int finished;
    struct fork_branch *next;
};

struct pbx_call {
    char *sip_call_id;
    char backbone_call_id[33];
    int is_backbone_call;               // 1 if going to backbone, 0 if ext-to-ext

    struct sockaddr_storage caller_addr;
    char *caller_ext;
    char *callee_did;                    // rewritten DID for backbone, or target ext
    int cseq_num;

    /* Caller-side dialog headers (caller's INVITE + gateway's to-tag) */
    char *caller_via;
    char *caller_from;
    char *caller_to;        /* includes gateway's to-tag after 200 OK */
    char *caller_contact;
    char gw_tag[16];        /* gateway-generated to-tag for caller dialog */

    /* Callee-side dialog headers (from callee's 200 OK) */
    char *callee_from;      /* From in callee's 200 OK */
    char *callee_to;        /* To in callee's 200 OK (with callee's tag) */

    /* RTP */
    struct rtp_pair *rtp_caller;
    struct rtp_pair *rtp_callee;

    /* Fork (backbone→ext) */
    struct fork_branch *branches;

    enum call_state state;
    time_t started_at;      /* time call became ACTIVE, for duration logging */
    struct pbx_call *next;
};

struct pbx_state {
    struct gw_config *config;
    struct backbone_state *backbone;
    int *sip_fds;
    struct rtp_alloc_ctx rtp_ctx;
    struct pbx_call *calls;
    pt_task_t *busy_retry_task;
    pt_task_t *sip_task;
    pt_task_t *cleanup_task;
};

struct pbx_state *pbx_create(struct gw_config *cfg);
void pbx_free(struct pbx_state *ps);

/* Scheduler tasks (for daemon to register) */
int sip_recv_task(int64_t ts, struct pt_task *pt);
int busy_retry_task(int64_t ts, struct pt_task *pt);
int cleanup_task(int64_t ts, struct pt_task *pt);

/* Called by backbone module when it receives an invite line */
void pbx_handle_backbone_invite(struct pbx_state *ps, const char *call_id,
                                const char *did, const char *cid);

/* Called by backbone module on incoming protocol lines */
void pbx_on_backbone_ringing(struct pbx_state *s, const char *call_id);
void pbx_on_backbone_answer(struct pbx_state *s, const char *call_id);
void pbx_on_backbone_cancel(struct pbx_state *s, const char *call_id);
void pbx_on_backbone_media(struct pbx_state *s, const char *call_id, const uint8_t *data, size_t len);
void pbx_on_backbone_bye(struct pbx_state *s, const char *call_id);

/* Call management */
struct pbx_call *pbx_find_by_sip_id(struct pbx_state *s, const char *sip_call_id);
struct pbx_call *pbx_find_by_backbone_id(struct pbx_state *s, const char *bb_call_id);
void pbx_call_remove(struct pbx_state *s, struct pbx_call *call);

#endif
