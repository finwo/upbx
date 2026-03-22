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

static socklen_t get_addrlen(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) return sizeof(struct sockaddr_in);
    return sizeof(struct sockaddr_in6);
}

void rtp_ctx_init(struct rtp_alloc_ctx *ctx, int min, int max) {
    ctx->port_min = min;
    ctx->port_max = max;
    ctx->next_port = min;
}

static int rtp_task(int64_t ts, struct pt_task *pt) {
    struct rtp_pair *rp = pt->udata;

    int fds[2] = {1, rp->fd};
    int ready_fd = sched_has_data(fds);
    if (ready_fd < 0) return SCHED_RUNNING;

    uint8_t buf[1500];
    struct sockaddr_storage src;
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(ready_fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
    if (n <= 0) {
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            log_warn("rtp: recvfrom error on port %d: %s (errno=%d)", rp->port, strerror(errno), errno);
        return SCHED_RUNNING;
    }

    if (!rp->logged_incoming) {
        char ip[INET6_ADDRSTRLEN];
        int port;
        if (src.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&src)->sin_addr, ip, sizeof(ip));
            port = ntohs(((struct sockaddr_in *)&src)->sin_port);
        } else {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&src)->sin6_addr, ip, sizeof(ip));
            port = ntohs(((struct sockaddr_in6 *)&src)->sin6_port);
        }
        log_info("rtp: first inbound RTP for %s from %s:%d (local port %d, %zd bytes)",
                 rp->call_id, ip, port, rp->port, n);
        rp->logged_incoming = 1;
    }

    if (!rp->learned_ext && !rp->addr_from_sdp) {
        rp->ext_addr = src;
        rp->learned_ext = 1;
    }

    if (rp->is_backbone_dir && rp->backbone) {
        backbone_send_media(rp->backbone, rp->call_id, rp->stream_id, buf, (size_t)n);
    } else if (rp->peer && rp->peer->learned_ext) {
        sendto(rp->peer->fd, buf, n, 0,
               (struct sockaddr *)&rp->peer->ext_addr,
               get_addrlen(&rp->peer->ext_addr));
    }

    return SCHED_RUNNING;
}

struct rtp_pair *rtp_alloc(struct rtp_alloc_ctx *ctx, int af) {
    struct rtp_pair *rp = calloc(1, sizeof(*rp));
    if (!rp) return NULL;
    rp->stream_id = -1;

    int attempts = 0;
    int port_count = (ctx->port_max - ctx->port_min) / 2 + 1;

    while (attempts < port_count) {
        int fd = socket(af, SOCK_DGRAM, 0);
        if (fd < 0) {
            free(rp);
            return NULL;
        }

        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(addr));
        addr.ss_family = af;
        socklen_t addr_len;
        if (af == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in *)&addr;
            a->sin_addr.s_addr = htonl(INADDR_ANY);
            a->sin_port = htons((uint16_t)ctx->next_port);
            addr_len = sizeof(struct sockaddr_in);
        } else {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
            a->sin6_addr = in6addr_any;
            a->sin6_port = htons((uint16_t)ctx->next_port);
            addr_len = sizeof(struct sockaddr_in6);
        }

        if (bind(fd, (struct sockaddr *)&addr, addr_len) == 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);

            rp->fd = fd;
            rp->port = ctx->next_port;

            rp->task = sched_create(rtp_task, rp);

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
    sendto(rp->fd, data, len, 0,
           (struct sockaddr *)&rp->ext_addr,
           get_addrlen(&rp->ext_addr));
}

void rtp_set_remote(struct rtp_pair *rp, const char *host, int port) {
    if (!rp || !host) return;
    memset(&rp->ext_addr, 0, sizeof(rp->ext_addr));

    /* Try IPv4 first */
    struct sockaddr_in *a4 = (struct sockaddr_in *)&rp->ext_addr;
    a4->sin_family = AF_INET;
    a4->sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a4->sin_addr) == 1) {
        rp->learned_ext = 1;
        rp->addr_from_sdp = 1;
        return;
    }

    /* Try IPv6 */
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&rp->ext_addr;
    a6->sin6_family = AF_INET6;
    a6->sin6_port = htons((uint16_t)port);
    if (inet_pton(AF_INET6, host, &a6->sin6_addr) == 1) {
        rp->learned_ext = 1;
        rp->addr_from_sdp = 1;
        return;
    }

    log_warn("rtp: failed to parse remote address: %s", host);
}
