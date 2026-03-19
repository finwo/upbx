#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "finwo/scheduler.h"
#include "backbone/backbone.h"
#include "rxi/log.h"
#include "rtp/rtp.h"

void rtp_ctx_init(struct rtp_alloc_ctx *ctx, int min, int max) {
    ctx->port_min = min;
    ctx->port_max = max;
    ctx->next_port = min;
}

static int rtp_task(int64_t ts, struct pt_task *pt) {
    struct rtp_pair *rp = pt->udata;

    int fds[2] = {1, rp->fd};
    if (sched_has_data(fds) < 0) return SCHED_RUNNING;

    uint8_t buf[1500];
    struct sockaddr_storage src;
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(rp->fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
    if (n <= 0) return SCHED_RUNNING;

    // Learn extension address from first packet
    if (!rp->learned_ext) {
        rp->ext_addr = src;
        rp->learned_ext = 1;
    }

    if (rp->is_backbone_dir && rp->backbone) {
        // Forward to backbone as hex-encoded media
        backbone_send_media(rp->backbone, rp->call_id, buf, (size_t)n);
    } else if (rp->peer && rp->peer->learned_ext) {
        // Ext-to-ext: forward raw RTP to peer's learned address
        sendto(rp->peer->fd, buf, n, 0,
               (struct sockaddr *)&rp->peer->ext_addr,
               sizeof(rp->peer->ext_addr));
    }

    return SCHED_RUNNING;
}

struct rtp_pair *rtp_alloc(struct rtp_alloc_ctx *ctx) {
    struct rtp_pair *rp = calloc(1, sizeof(*rp));
    if (!rp) return NULL;

    int attempts = 0;
    int port_count = (ctx->port_max - ctx->port_min) / 2 + 1;

    while (attempts < port_count) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            free(rp);
            return NULL;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons((uint16_t)ctx->next_port);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            // Set nonblocking
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);

            rp->fd = fd;
            rp->port = ctx->next_port;

            // Schedule task
            rp->task = sched_create(rtp_task, rp);

            // Advance next_port by 2, wrap around
            ctx->next_port += 2;
            if (ctx->next_port > ctx->port_max) {
                ctx->next_port = ctx->port_min;
            }

            return rp;
        }

        close(fd);

        if (errno != EADDRINUSE) {
            free(rp);
            return NULL;
        }

        ctx->next_port += 2;
        if (ctx->next_port > ctx->port_max) {
            ctx->next_port = ctx->port_min;
        }
        attempts++;
    }

    log_error("rtp", "no available ports in range");
    free(rp);
    return NULL;
}

void rtp_free(struct rtp_pair *rp) {
    if (!rp) return;
    if (rp->task) sched_remove(rp->task);
    if (rp->fd >= 0) close(rp->fd);
    free(rp);
}

void rtp_send_to_ext(struct rtp_pair *rp, const uint8_t *data, size_t len) {
    if (!rp->learned_ext) return;
    sendto(rp->fd, data, len, 0, (struct sockaddr *)&rp->ext_addr, sizeof(rp->ext_addr));
}
