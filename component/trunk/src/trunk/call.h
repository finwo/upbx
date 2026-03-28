#ifndef TRK_CALL_H
#define TRK_CALL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "finwo/scheduler.h"
#include "finwo/mindex.h"
#include "rtp/rtp.h"

enum call_state {
    CALL_WAITING,
    CALL_RINGING,
    CALL_ACTIVE,
    CALL_ENDED,
};

struct trunk_call {
    char *call_id;
    size_t call_id_len;
    char *sip_call_id;

    struct sockaddr_storage trunk_addr;
    int   trunk_fd;
    char  *trunk_did;
    char  *trunk_cid;
    int   cseq_num;
    char  branch[32];
    char  from_tag[32];
    char  *trunk_via;
    char  *trunk_from;
    char  *trunk_to;
    char  *trunk_contact;
    char  gw_tag[16];

    struct rtp_pair *rtp;
    char  *remote_sdp_host;
    int   remote_sdp_port;

    enum call_state state;

    int   delay_active;
    int64_t delay_started;

    char  *backbone_tags;
};

struct call_key {
    const char *call_id;
    size_t call_id_len;
};

int  call_cmp(const void *a, const void *b, void *udata);
void call_purge(void *item, void *udata);

struct trunk_call *call_create(struct mindex_t *mindex, const char *call_id,
                               const char *sip_call_id);
struct trunk_call *call_lookup(struct mindex_t *mindex, const char *call_id);
void               call_destroy(struct mindex_t *mindex, struct trunk_call *call);

#endif