#ifndef GW_RTP_H
#define GW_RTP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "finwo/scheduler.h"

struct backbone_state; // forward

struct rtp_pair {
    int fd;
    int port;
    struct sockaddr_storage ext_addr;
    int learned_ext;
    struct backbone_state *backbone;
    char call_id[64];
    int stream_id;           // RTP payload type, -1 if unknown
    int is_backbone_dir;
    int logged_incoming;     // diagnostics: first inbound RTP logged
    struct rtp_pair *peer;
    pt_task_t *task;
    struct rtp_pair *next;
};

struct rtp_alloc_ctx {
    int next_port;
    int port_min;
    int port_max;
};

void rtp_ctx_init(struct rtp_alloc_ctx *ctx, int min, int max);
struct rtp_pair *rtp_alloc(struct rtp_alloc_ctx *ctx);
void rtp_free(struct rtp_pair *rp);

void rtp_send_to_ext(struct rtp_pair *rp, const uint8_t *data, size_t len);

#endif
