#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "domain/protothreads.h"
#include "domain/scheduler.h"
#include "common/socket_util.h"
#include "common/hexdump.h"
#include "infrastructure/config.h"
#include "domain/pbx/sip/transport_udp.h"
#include "domain/pbx/sip/sip_message.h"
#include "domain/pbx/sip/sdp_parse.h"
#include "domain/pbx/sip_handler.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/call.h"
#include "domain/pbx/nonce.h"

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

static char *build_response(sip_message_t *msg, int code, const char *reason, size_t *out_len) {
    size_t cap = 1024;
    char *resp = malloc(cap);
    if (!resp) return NULL;
    
    size_t used = 0;
    int n;
    
    n = snprintf(resp + used, cap - used, "SIP/2.0 %d %s\r\n", code, reason);
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

static char *build_response_with_sdp(sip_message_t *msg, int code, const char *reason, const char *sdp, size_t sdp_len, size_t *out_len) {
    size_t cap = 2048 + sdp_len;
    char *resp = malloc(cap);
    if (!resp) return NULL;
    
    size_t used = 0;
    int n;
    
    n = snprintf(resp + used, cap - used, "SIP/2.0 %d %s\r\n", code, reason);
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
    
    n = snprintf(resp + used, cap - used, "Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n", (int)sdp_len);
    if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
    used += (size_t)n;
    
    if (sdp && sdp_len > 0) {
        if (used + sdp_len >= cap) {
            free(resp);
            return NULL;
        }
        memcpy(resp + used, sdp, sdp_len);
        used += sdp_len;
    }
    
    *out_len = used;
    return resp;
}

static char *build_invite_to_destination(sip_message_t *msg, const char *dest_ext, 
                                         const char *call_id, const char *from_tag,
                                         const char *dest_ip, int dest_port,
                                         const char *sdp, size_t sdp_len,
                                         const char *pbx_addr,
                                         size_t *out_len) {
    size_t cap = 2048 + sdp_len;
    char *inv = malloc(cap);
    if (!inv) return NULL;
    
    size_t used = 0;
    int n;
    
    n = snprintf(inv + used, cap - used, "INVITE sip:%s@%s:%d SIP/2.0\r\n", 
                 dest_ext, dest_ip, dest_port);
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "Via: SIP/2.0/UDP %s;branch=z9hG4bKupbx%x\r\n", 
                 pbx_addr, (unsigned int)time(NULL));
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "From: <sip:%%from_ext%%@%s>;tag=%s\r\n", 
                 pbx_addr, from_tag);
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "To: <sip:%s@%s>\r\n", dest_ext, pbx_addr);
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "Call-ID: %s\r\n", call_id);
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "CSeq: 1 INVITE\r\n");
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "Contact: <sip:pbx@%s:5060>\r\n", pbx_addr);
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    n = snprintf(inv + used, cap - used, "Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n", 
                 (int)sdp_len);
    if (n < 0 || (size_t)n >= cap - used) { free(inv); return NULL; }
    used += (size_t)n;
    
    if (sdp && sdp_len > 0) {
        if (used + sdp_len >= cap) {
            free(inv);
            return NULL;
        }
        memcpy(inv + used, sdp, sdp_len);
        used += sdp_len;
    }
    
    *out_len = used;
    return inv;
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
    const char *listen_str = upbx_sec ? resp_map_get_string(upbx_sec, "address") : NULL;
    if (!listen_str || !listen_str[0]) {
        listen_str = ":5060";
    }
    if (strncmp(listen_str, "udp://", 6) == 0) {
        listen_str = listen_str + 6;
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
    call_init();

    sip_fds = udp_recv(listen_str, NULL, "5060");
    if (!sip_fds || sip_fds[0] == 0) {
        log_error("sip_udp: failed to create socket on %s", listen_str);
        PT_EXIT(pt);
    }

    log_info("sip_udp: listening on %s", listen_str);

    for (;;) {
        PT_WAIT_UNTIL(pt, domain_schedmod_has_data(sip_fds, &sip_ready_fds) > 0);

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
            } else if (sip_msg.method_len == 6 && strncasecmp(sip_msg.method, "INVITE", 6) == 0) {
                char from_ext[64] = {0};
                char to_ext[64] = {0};
                char call_id[256] = {0};
                char from_tag[64] = {0};
                
                sip_header_uri_extract_user(&sip_msg, "From", from_ext, sizeof(from_ext));
                sip_header_uri_extract_user(&sip_msg, "To", to_ext, sizeof(to_ext));
                sip_message_header_copy(&sip_msg, "Call-ID", call_id, sizeof(call_id));
                
                const char *from_header = sip_message_header_get(&sip_msg, "From", NULL);
                if (from_header) {
                    const char *tag = strstr(from_header, ";tag=");
                    if (tag) {
                        tag += 5;
                        const char *end = tag;
                        while (*end && *end != ';' && *end != '>' && *end != '\r' && *end != '\n') end++;
                        size_t tag_len = (size_t)(end - tag);
                        if (tag_len < sizeof(from_tag)) {
                            memcpy(from_tag, tag, tag_len);
                            from_tag[tag_len] = '\0';
                        }
                    }
                }
                
                if (!from_ext[0] || !to_ext[0] || !call_id[0] || !from_tag[0]) {
                    resp = build_response(&sip_msg, 400, "Bad Request", &resp_len);
                } else {
                    const char *sdp = sip_msg.body;
                    size_t sdp_len = sip_msg.body_len;
                    
                    char *out_sdp = NULL;
                    size_t out_sdp_len = 0;
                    
                    int r = call_route_invite(from_ext, to_ext, call_id, from_tag, 
                                             sdp, sdp_len, src_ip, src_port,
                                             &out_sdp, &out_sdp_len);
                    
                    if (r == -1) {
                        resp = build_response(&sip_msg, 403, "Forbidden", &resp_len);
                    } else if (r == -2) {
                        resp = build_response(&sip_msg, 404, "Not Found", &resp_len);
                    } else {
                        resp = build_response_with_sdp(&sip_msg, 100, "Trying", 
                                                        out_sdp, out_sdp_len, &resp_len);
                        if (out_sdp) free(out_sdp);
                        
                        call_t *c = call_find(call_id);
                        if (c) {
                            char dest_ip[INET6_ADDRSTRLEN] = {0};
                            int dest_port = 5060;
                            if (c->dest_addr.ss_family == AF_INET) {
                                struct sockaddr_in *sin = (struct sockaddr_in *)&c->dest_addr;
                                inet_ntop(AF_INET, &sin->sin_addr, dest_ip, sizeof(dest_ip));
                                dest_port = ntohs(sin->sin_port);
                            } else if (c->dest_addr.ss_family == AF_INET6) {
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c->dest_addr;
                                inet_ntop(AF_INET6, &sin6->sin6_addr, dest_ip, sizeof(dest_ip));
                                dest_port = ntohs(sin6->sin6_port);
                            }
                            
                            char pbx_addr[64] = "0.0.0.0";
                            const char *listen_str2 = upbx_sec ? resp_map_get_string(upbx_sec, "address") : NULL;
                            if (listen_str2) {
                                const char *colon = strrchr(listen_str2, ':');
                                if (colon) {
                                    size_t len = (size_t)(colon - listen_str2);
                                    if (len < sizeof(pbx_addr)) {
                                        memcpy(pbx_addr, listen_str2, len);
                                        pbx_addr[len] = '\0';
                                    }
                                }
                            }
                            
                            char *inv = NULL;
                            size_t inv_len = 0;
                            inv = build_invite_to_destination(&sip_msg, c->dest_ext, call_id, from_tag,
                                                             dest_ip, dest_port, c->dest_rtp_ip, 
                                                             strlen(c->dest_rtp_ip),
                                                             pbx_addr, &inv_len);
                            if (inv) {
                                int fd = socket(c->dest_addr.ss_family, SOCK_DGRAM, 0);
                                if (fd >= 0) {
                                    socklen_t dst_len = (c->dest_addr.ss_family == AF_INET)
                                        ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6);
                                    sendto(fd, inv, inv_len, 0, 
                                          (struct sockaddr *)&c->dest_addr, dst_len);
                                    close(fd);
                                }
                                free(inv);
                            }
                        }
                    }
                }
            } else if (sip_msg.method_len == 6 && strncasecmp(sip_msg.method, "OPTIONS", 6) == 0) {
                resp = build_method_not_allowed(&sip_msg, &resp_len);
            } else if (sip_msg.method_len == 3 && strncasecmp(sip_msg.method, "ACK", 3) == 0) {
                resp = NULL;
            } else if (sip_msg.method_len == 3 && strncasecmp(sip_msg.method, "BYE", 3) == 0) {
                char call_id[256] = {0};
                sip_message_header_copy(&sip_msg, "Call-ID", call_id, sizeof(call_id));
                if (call_id[0]) {
                    call_handle_bye(call_id);
                }
                resp = build_response(&sip_msg, 200, "OK", &resp_len);
            } else if (sip_msg.method_len == 6 && strncasecmp(sip_msg.method, "CANCEL", 6) == 0) {
                char call_id[256] = {0};
                sip_message_header_copy(&sip_msg, "Call-ID", call_id, sizeof(call_id));
                if (call_id[0]) {
                    call_t *c = call_find(call_id);
                    if (c) {
                        char src_ext[64] = {0};
                        char from_header[256] = {0};
                        sip_message_header_copy(&sip_msg, "From", from_header, sizeof(from_header));
                        sip_header_uri_extract_user(&sip_msg, "From", src_ext, sizeof(src_ext));
                        
                        int authorized = (strcmp(src_ext, c->source_ext) == 0 || 
                                        strcmp(src_ext, c->dest_ext) == 0);
                        
                        if (authorized) {
                            call_handle_cancel(call_id);
                            
                            char dest_ip[INET6_ADDRSTRLEN] = {0};
                            int dest_port = 5060;
                            if (c->dest_addr.ss_family == AF_INET) {
                                struct sockaddr_in *sin = (struct sockaddr_in *)&c->dest_addr;
                                inet_ntop(AF_INET, &sin->sin_addr, dest_ip, sizeof(dest_ip));
                                dest_port = ntohs(sin->sin_port);
                            } else if (c->dest_addr.ss_family == AF_INET6) {
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c->dest_addr;
                                inet_ntop(AF_INET6, &sin6->sin6_addr, dest_ip, sizeof(dest_ip));
                                dest_port = ntohs(sin6->sin6_port);
                            }
                            
                            char cancel_cmd[512];
                            int cancel_len = snprintf(cancel_cmd, sizeof(cancel_cmd),
                                "CANCEL sip:%s@%s:%d SIP/2.0\r\n"
                                "Via: SIP/2.0/UDP %%via%%\r\n"
                                "From: %s\r\n"
                                "To: %s\r\n"
                                "Call-ID: %s\r\n"
                                "CSeq: %d CANCEL\r\n"
                                "Content-Length: 0\r\n\r\n",
                                c->dest_ext, dest_ip, dest_port,
                                from_header, "", call_id, 1);
                            
                            int fd = socket(c->dest_addr.ss_family, SOCK_DGRAM, 0);
                            if (fd >= 0 && cancel_len > 0) {
                                sendto(fd, cancel_cmd, (size_t)cancel_len, 0,
                                      (struct sockaddr *)&c->dest_addr,
                                      c->dest_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                                close(fd);
                            }
                        }
                    }
                }
                resp = build_response(&sip_msg, 200, "OK", &resp_len);
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
