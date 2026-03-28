#ifndef TRK_TRUNK_H
#define TRK_TRUNK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include "config/config.h"
#include "finwo/mindex.h"
#include "finwo/scheduler.h"
#include "rtp/rtp.h"
#include "call.h"

struct trunk_state {
    struct trk_config *config;
    struct backbone_state *backbone;
    int *sip_fds;
    char listen_addr[INET6_ADDRSTRLEN];

    struct sockaddr_storage target_addr;
    socklen_t target_addrlen;
    int target_af;

    int reg_registered;
    int64_t reg_refresh_at;
    int reg_expires;

    int64_t keepalive_last_send;

    struct rtp_alloc_ctx rtp_ctx;
    struct mindex_t *calls;
    pt_task_t *sip_task;
    pt_task_t *delay_task;
};

struct trunk_state *trunk_create(struct trk_config *cfg);
void trunk_free(struct trunk_state *ts);

int trunk_sip_recv_task(int64_t ts, struct pt_task *pt);
int trunk_delay_task(int64_t ts, struct pt_task *pt);

void trunk_on_backbone_invite(struct trunk_state *ts, const char *call_id,
                              const char *did, const char *cid,
                              const char *tags_str);

void trunk_on_backbone_ringing(struct trunk_state *s, const char *call_id,
                               const char *codec_tags);
void trunk_on_backbone_answer(struct trunk_state *s, const char *call_id,
                              const char *codec_tags);
void trunk_on_backbone_cancel(struct trunk_state *s, const char *call_id);
void trunk_on_backbone_media(struct trunk_state *s, const char *call_id,
                             const uint8_t *data, size_t len);
void trunk_on_backbone_bye(struct trunk_state *s, const char *call_id);

#endif