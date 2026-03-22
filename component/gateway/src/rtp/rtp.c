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

    int ready_fd = sched_has_data(rp->fds);
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

    /* Learn extension address from first packet */
    if (!rp->learned_ext) {
        rp->ext_addr = src;
        rp->learned_ext = 1;
    }

    if (rp->is_backbone_dir && rp->backbone) {
        /* Forward to backbone as hex-encoded media */
        backbone_send_media(rp->backbone, rp->call_id, rp->stream_id, buf, (size_t)n);
    } else if (rp->peer && rp->peer->learned_ext) {
        /* Ext-to-ext: forward raw RTP to peer's learned address from matching socket */
        int send_fd;
        if (rp->peer->ext_addr.ss_family == AF_INET6 && rp->peer->fd6 >= 0) {
            send_fd = rp->peer->fd6;
        } else {
            send_fd = rp->peer->fd;
        }
        sendto(send_fd, buf, n, 0,
               (struct sockaddr *)&rp->peer->ext_addr,
               get_addrlen(&rp->peer->ext_addr));
    }

    return SCHED_RUNNING;
}

struct rtp_pair *rtp_alloc(struct rtp_alloc_ctx *ctx) {
    struct rtp_pair *rp = calloc(1, sizeof(*rp));
    if (!rp) return NULL;
    rp->stream_id = -1;
    rp->fd = -1;
    rp->fd6 = -1;

    int attempts = 0;
    int port_count = (ctx->port_max - ctx->port_min) / 2 + 1;
    int port = ctx->next_port;

    while (attempts < port_count) {
        /* Try to bind BOTH IPv4 and IPv6 on this port */
        int fd4 = socket(AF_INET, SOCK_DGRAM, 0);
        int fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd4 < 0 && fd6 < 0) { free(rp); return NULL; }

        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        addr4.sin_port = htons((uint16_t)port);

        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons((uint16_t)port);

        int bound4 = 0, bound6 = 0;
        if (fd4 >= 0 && bind(fd4, (struct sockaddr *)&addr4, sizeof(addr4)) == 0) {
            bound4 = 1;
        }
        if (fd6 >= 0 && bind(fd6, (struct sockaddr *)&addr6, sizeof(addr6)) == 0) {
            bound6 = 1;
        }

        if (bound4 || bound6) {
            if (fd4 >= 0 && !bound4) { close(fd4); fd4 = -1; }
            if (fd6 >= 0 && !bound6) { close(fd6); fd6 = -1; }

            /* Set nonblocking */
            if (bound4) { int f = fcntl(fd4, F_GETFL, 0); fcntl(fd4, F_SETFL, f | O_NONBLOCK); }
            if (bound6) { int f = fcntl(fd6, F_GETFL, 0); fcntl(fd6, F_SETFL, f | O_NONBLOCK); }

            rp->fd = fd4 >= 0 ? fd4 : fd6;
            rp->fd6 = fd6;
            rp->port = port;

            /* Build fd array for sched_has_data: {count, fd1, fd2} */
            int n = 0;
            if (bound4) rp->fds[++n] = fd4;
            if (bound6) rp->fds[++n] = fd6;
            rp->fds[0] = n;

            rp->task = sched_create(rtp_task, rp);

            ctx->next_port += 2;
            if (ctx->next_port > ctx->port_max) ctx->next_port = ctx->port_min;
            return rp;
        }

        if (fd4 >= 0) close(fd4);
        if (fd6 >= 0) close(fd6);

        port += 2;
        if (port > ctx->port_max) port = ctx->port_min;
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
    if (rp->fd6 >= 0) close(rp->fd6);
    free(rp);
}

void rtp_send_to_ext(struct rtp_pair *rp, const uint8_t *data, size_t len) {
    if (!rp->learned_ext) return;
    sendto(rp->fd, data, len, 0,
           (struct sockaddr *)&rp->ext_addr,
           get_addrlen(&rp->ext_addr));
}
