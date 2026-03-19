#ifndef GW_BACKBONE_H
#define GW_BACKBONE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "finwo/scheduler.h"
#include "config/config.h"

struct pbx_state; // forward decl

enum backbone_phase {
    BACKBONE_DISCONNECTED,
    BACKBONE_WAIT_AUTH,
    BACKBONE_CONNECTED,
};

struct backbone_state {
    struct gw_config *config;
    struct gw_backbone *current;
    int fd;
    enum backbone_phase phase;
    char recv_buf[4096];
    size_t recv_len;
    time_t last_attempt;
    int fail_index;
    struct pbx_state *pbx;
    pt_task_t *task;
};

struct backbone_state *backbone_create(struct gw_config *cfg, struct pbx_state *pbx);
void backbone_free(struct backbone_state *bs);

void backbone_send_invite(struct backbone_state *s, const char *call_id, const char *did, const char *cid);
void backbone_send_ringing(struct backbone_state *s, const char *call_id);
void backbone_send_answer(struct backbone_state *s, const char *call_id);
void backbone_send_cancel(struct backbone_state *s, const char *call_id);
void backbone_send_media(struct backbone_state *s, const char *call_id, const uint8_t *rtp, size_t len);
void backbone_send_bye(struct backbone_state *s, const char *call_id);

#endif
