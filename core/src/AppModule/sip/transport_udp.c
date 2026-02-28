#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "SchedulerModule/protothreads.h"
#include "SchedulerModule/scheduler.h"
#include "common/socket_util.h"
#include "config.h"
#include "AppModule/sip/transport_udp.h"

#define UDP_BUF_SIZE 8192

static int *sip_fds = NULL;
static int *sip_ready_fds = NULL;

static char *sip_build_503_response(const char *via, const char *from, const char *to,
                                     const char *call_id, const char *cseq, size_t *out_len) {
    static const char *tmpl =
        "SIP/2.0 503 Service Unavailable\r\n"
        "Via: %s\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    size_t via_len = via ? strlen(via) : 0;
    size_t from_len = from ? strlen(from) : 0;
    size_t to_len = to ? strlen(to) : 0;
    size_t call_id_len = call_id ? strlen(call_id) : 0;
    size_t cseq_len = cseq ? strlen(cseq) : 0;

    size_t needed = strlen(tmpl) + via_len + from_len + to_len + call_id_len + cseq_len + 1;
    char *resp = malloc(needed);
    if (!resp) return NULL;

    snprintf(resp, needed, tmpl,
             via ? via : "",
             from ? from : "",
             to ? to : "",
             call_id ? call_id : "",
             cseq ? cseq : "");

    *out_len = strlen(resp);
    return resp;
}

static int sip_header_copy_static(const char *buf, size_t len, const char *name,
                                   char *out, size_t out_size) {
    const char *p = buf;
    const char *end = buf + len;
    size_t name_len = strlen(name);

    while (p < end) {
        const char *line_end = memchr(p, '\r', end - p);
        if (!line_end) line_end = memchr(p, '\n', end - p);
        if (!line_end) line_end = end;

        size_t line_len = line_end - p;

        if (line_len > name_len + 1 &&
            strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *val_start = p + name_len + 1;
            while (val_start < line_end && (*val_start == ' ' || *val_start == '\t'))
                val_start++;

            size_t val_len = line_end - val_start;
            if (val_len >= out_size) val_len = out_size - 1;
            memcpy(out, val_start, val_len);
            out[val_len] = '\0';
            return 1;
        }

        if (*line_end == '\r' && line_end + 1 < end && *(line_end + 1) == '\n')
            p = line_end + 2;
        else if (*line_end == '\n')
            p = line_end + 1;
        else
            p = line_end;
    }

    return 0;
}

PT_THREAD(sip_transport_udp_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
    (void)timestamp;
    (void)task;

    static char buf[UDP_BUF_SIZE];
    static struct sockaddr_storage src_addr;
    static socklen_t src_len;

    PT_BEGIN(pt);

    PT_WAIT_UNTIL(pt, global_cfg);

    resp_object *upbx_sec = resp_map_get(global_cfg, "upbx");
    const char *listen_str = upbx_sec ? resp_map_get_string(upbx_sec, "listen") : NULL;
    if (!listen_str || !listen_str[0]) {
        listen_str = "0.0.0.0:5060";
    }

    sip_fds = udp_recv(listen_str, NULL, "5060");
    if (!sip_fds || sip_fds[0] == 0) {
        log_error("sip_udp: failed to create socket on %s", listen_str);
        PT_EXIT(pt);
    }

    log_info("sip_udp: listening on %s", listen_str);

    for (;;) {
        PT_WAIT_UNTIL(pt, schedmod_has_data(sip_fds, &sip_ready_fds) > 0);

        if (!sip_ready_fds || sip_ready_fds[0] == 0) {
            PT_YIELD(pt);
            continue;
        }

        for (int r = 1; r <= sip_ready_fds[0]; r++) {
            int ready_fd = sip_ready_fds[r];

            src_len = sizeof(src_addr);
            ssize_t n = recvfrom(ready_fd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&src_addr, &src_len);

            if (n <= 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_error("sip_udp: recvfrom failed: %s", strerror(errno));
                }
                continue;
            }

            buf[n] = '\0';

            char src_ip[INET6_ADDRSTRLEN] = {0};
            int src_port = 0;
            if (src_addr.ss_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)&src_addr;
                inet_ntop(AF_INET, &sin->sin_addr, src_ip, sizeof(src_ip));
                src_port = ntohs(sin->sin_port);
            } else if (src_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
                inet_ntop(AF_INET6, &sin6->sin6_addr, src_ip, sizeof(src_ip));
                src_port = ntohs(sin6->sin6_port);
            }

            log_trace("sip_udp: received %zd bytes from %s:%d", n, src_ip, src_port);
            log_trace("sip_udp: message:\n%.*s", (int)n, buf);

            char via[512] = {0};
            char from[256] = {0};
            char to[256] = {0};
            char call_id[128] = {0};
            char cseq[64] = {0};

            sip_header_copy_static(buf, (size_t)n, "Via", via, sizeof(via));
            sip_header_copy_static(buf, (size_t)n, "From", from, sizeof(from));
            sip_header_copy_static(buf, (size_t)n, "To", to, sizeof(to));
            sip_header_copy_static(buf, (size_t)n, "Call-ID", call_id, sizeof(call_id));
            sip_header_copy_static(buf, (size_t)n, "CSeq", cseq, sizeof(cseq));

            size_t resp_len;
            char *resp = sip_build_503_response(via, from, to, call_id, cseq, &resp_len);
            if (resp) {
                socklen_t dst_len = (src_addr.ss_family == AF_INET)
                    ? sizeof(struct sockaddr_in)
                    : sizeof(struct sockaddr_in6);
                ssize_t sent = sendto(ready_fd, resp, resp_len, 0,
                                      (struct sockaddr *)&src_addr, dst_len);
                if (sent > 0) {
                    log_trace("sip_udp: sent %zd bytes 503 response", sent);
                } else {
                    log_error("sip_udp: sendto failed: %s", strerror(errno));
                }
                free(resp);
            }
        }
        free(sip_ready_fds);
        sip_ready_fds = NULL;
    }

    if (sip_fds) {
        for (int i = 1; i <= sip_fds[0]; i++) {
            close(sip_fds[i]);
        }
        free(sip_fds);
        sip_fds = NULL;
    }

    PT_END(pt);
}
