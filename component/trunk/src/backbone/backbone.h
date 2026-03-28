#ifndef TRK_BACKBONE_H
#define TRK_BACKBONE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "finwo/scheduler.h"
#include "config/config.h"

struct trunk_state;

enum backbone_phase {
    BACKBONE_DISCONNECTED,
    BACKBONE_WAIT_AUTH,
    BACKBONE_CONNECTED,
};

struct backbone_state {
    struct trk_config *config;
    struct trk_backbone *current;
    int fd;
    enum backbone_phase phase;
    char recv_buf[4096];
    size_t recv_len;
    time_t last_attempt;
    int fail_index;
    struct trunk_state *trunk;
    pt_task_t *task;
};

struct backbone_state *backbone_create(struct trk_config *cfg, struct trunk_state *trunk);
void backbone_free(struct backbone_state *bs);

void backbone_send_invite(struct backbone_state *s, const char *call_id,
                          const char *did, const char *cid,
                          const char *tags);
void backbone_send_ringing(struct backbone_state *s, const char *call_id, const char *tags);
void backbone_send_answer(struct backbone_state *s, const char *call_id, const char *tags);
void backbone_send_cancel(struct backbone_state *s, const char *call_id);
void backbone_send_media(struct backbone_state *s, const char *call_id, const uint8_t *rtp, size_t len);
void backbone_send_bye(struct backbone_state *s, const char *call_id);

#endif
