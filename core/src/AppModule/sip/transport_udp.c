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
#include "common/hexdump.h"
#include "config.h"
#include "AppModule/sip/transport_udp.h"
#include "AppModule/sip/sip_message.h"
#include "AppModule/pbx/sip_handler.h"
#include "AppModule/pbx/registration.h"
#include "AppModule/pbx/nonce.h"

#define UDP_BUF_SIZE 8192

static int *sip_fds = NULL;
static int *sip_ready_fds = NULL;

static char *build_method_not_allowed(sip_message_t *msg, size_t *out_len) {
    size_t cap = 1024;
    char *resp = malloc(cap);
    if (!resp) return NULL;
    
    size_t used = 0;
    int n;
    
    n = snprintf(resp + used, cap - used, "SIP/2.0 405 Method Not Allowed\r\n");
    if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
    used += (size_t)n;
    
    size_t via_len;
    const char *via = sip_message_header_get(msg, "Via", &via_len);
    if (via && via_len > 0) {
        n = snprintf(resp + used, cap - used, "Via: %.*s\r\n", (int)via_len, via);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t from_len;
    const char *from = sip_message_header_get(msg, "From", &from_len);
    if (from && from_len > 0) {
        n = snprintf(resp + used, cap - used, "From: %.*s\r\n", (int)from_len, from);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t to_len;
    const char *to = sip_message_header_get(msg, "To", &to_len);
    if (to && to_len > 0) {
        n = snprintf(resp + used, cap - used, "To: %.*s\r\n", (int)to_len, to);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t call_id_len;
    const char *call_id = sip_message_header_get(msg, "Call-ID", &call_id_len);
    if (call_id && call_id_len > 0) {
        n = snprintf(resp + used, cap - used, "Call-ID: %.*s\r\n", (int)call_id_len, call_id);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t cseq_len;
    const char *cseq = sip_message_header_get(msg, "CSeq", &cseq_len);
    if (cseq && cseq_len > 0) {
        n = snprintf(resp + used, cap - used, "CSeq: %.*s\r\n", (int)cseq_len, cseq);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    n = snprintf(resp + used, cap - used, "Content-Length: 0\r\n\r\n");
    if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
    used += (size_t)n;
    
    *out_len = used;
    return resp;
}

PT_THREAD(sip_transport_udp_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
    (void)timestamp;
    (void)task;

    static char buf[UDP_BUF_SIZE];
    static struct sockaddr_storage src_addr;
    static socklen_t src_len;
    static sip_message_t sip_msg;

    log_trace("sip_udp: protothread entry");
    PT_BEGIN(pt);

    PT_WAIT_UNTIL(pt, global_cfg);

    resp_object *upbx_sec = resp_map_get(global_cfg, "upbx");
    const char *listen_str = upbx_sec ? resp_map_get_string(upbx_sec, "listen") : NULL;
    if (!listen_str || !listen_str[0]) {
        listen_str = "0.0.0.0:5060";
    }

    const char *secret = upbx_sec ? resp_map_get_string(upbx_sec, "secret") : NULL;
    if (secret) {
        nonce_set_secret(secret);
    } else {
        char auto_secret[33];
        for (int i = 0; i < 32; i++) {
            auto_secret[i] = "0123456789abcdef"[rand() % 16];
        }
        auto_secret[32] = '\0';
        nonce_set_secret(auto_secret);
        log_info("sip_udp: auto-generated secret (add 'secret = %s' to [upbx] section)", auto_secret);
    }

    const char *reg_dir = upbx_sec ? resp_map_get_string(upbx_sec, "registrations") : NULL;
    if (reg_dir) {
        registration_set_dir(reg_dir);
    }
    registration_init();

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

            if (sip_message_parse(buf, (size_t)n, &sip_msg) != 0) {
                log_warn("sip_udp: failed to parse SIP message from %s:%d", src_ip, src_port);
                log_hexdump_trace(buf, (size_t)n);
                continue;
            }

            size_t resp_len = 0;
            char *resp = NULL;

            if (!sip_is_request(&sip_msg)) {
                log_trace("sip_udp: ignoring SIP response from %s:%d", src_ip, src_port);
                sip_message_free(&sip_msg);
                continue;
            }

            if (sip_msg.method_len == 8 && strncasecmp(sip_msg.method, "REGISTER", 8) == 0) {
                resp = sip_handle_register(&sip_msg, &src_addr, &resp_len);
            } else if (sip_msg.method_len == 6 && strncasecmp(sip_msg.method, "OPTIONS", 6) == 0) {
                resp = build_method_not_allowed(&sip_msg, &resp_len);
            } else {
                resp = build_method_not_allowed(&sip_msg, &resp_len);
            }

            sip_message_free(&sip_msg);

            if (resp) {
                socklen_t dst_len = (src_addr.ss_family == AF_INET)
                    ? sizeof(struct sockaddr_in)
                    : sizeof(struct sockaddr_in6);
                ssize_t sent = sendto(ready_fd, resp, resp_len, 0,
                                      (struct sockaddr *)&src_addr, dst_len);
                if (sent > 0) {
                    log_trace("sip_udp: sent %zd bytes response", sent);
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
