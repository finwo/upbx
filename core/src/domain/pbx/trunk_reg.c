#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "rxi/log.h"
#include "common/resp.h"
#include "infrastructure/config.h"
#include "common/socket_util.h"
#include "common/digest_auth.h"
#include "domain/pbx/sip/sip_message.h"
#include "domain/pbx/trunk_reg.h"

#ifndef UPBX_VERSION_STR
#define UPBX_VERSION_STR "unknown"
#endif

static trunk_reg_t *trunks[TRUNK_REG_MAX_TRUNKS];
static size_t trunk_count = 0;

static void trunk_free(trunk_reg_t *t) {
    if (!t) return;
    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }
    free(t->name);
    free(t->address);
    free(t->host);
    free(t->username);
    free(t->password);
    free(t->did);
    free(t);
}

static int parse_address(const char *address, char *host_out, size_t host_size, int *port_out) {
    if (!address || !host_out || !port_out) return -1;
    
    *port_out = 5060;
    
    if (strncmp(address, "udp://", 6) != 0) {
        log_error("trunk_reg: address must start with udp://");
        return -1;
    }
    
    const char *host_start = address + 6;
    const char *port_sep = strrchr(host_start, ':');
    
    if (port_sep) {
        size_t host_len = (size_t)(port_sep - host_start);
        if (host_len >= host_size) return -1;
        memcpy(host_out, host_start, host_len);
        host_out[host_len] = '\0';
        *port_out = atoi(port_sep + 1);
        if (*port_out <= 0 || *port_out > 65535) {
            *port_out = 5060;
        }
    } else {
        strncpy(host_out, host_start, host_size - 1);
        host_out[host_size - 1] = '\0';
    }
    
    if (host_out[0] == '\0') return -1;
    
    return 0;
}

static void generate_call_id(trunk_reg_t *t) {
    snprintf(t->call_id, sizeof(t->call_id), "%llx@upbx",
             (unsigned long long)time(NULL) ^ ((unsigned long long)(uintptr_t)t & 0xFFFFFFFF));
}

static void generate_branch(trunk_reg_t *t) {
    snprintf(t->branch, sizeof(t->branch), "z9hG4bK%llx",
             (unsigned long long)time(NULL) ^ ((unsigned long long)(uintptr_t)t >> 4));
}

static int build_register(trunk_reg_t *t, char *buf, size_t buf_size, const char *realm, const char *nonce) {
    time_t now = time(NULL);
    
    const char *auth_header = "";
    char auth_buf[1024] = "";
    
    if (realm && nonce && t->username && t->password) {
        char uri[256];
        snprintf(uri, sizeof(uri), "sip:%s:%d", t->host, t->port);

        HASHHEX ha1, ha2, response;
        digest_calc_ha1(t->username, realm, t->password, ha1);
        digest_calc_ha2("REGISTER", uri, ha2);
        digest_calc_response(ha1, nonce, ha2, response);

        snprintf(auth_buf, sizeof(auth_buf),
            "Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\","
            "response=\"%s\"",
            t->username, realm, nonce, uri, response);
        auth_header = auth_buf;
    }
    
    int len = snprintf(buf, buf_size,
        "REGISTER sip:%s:%d SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%d;branch=%s\r\n"
        "From: <sip:%s@%s>;tag=%llx\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %u REGISTER\r\n"
        "Contact: <sip:%s@%s:%d>\r\n"
        "Expires: %d\r\n"
        "Max-Forwards: 70\r\n"
        "User-Agent: upbx/%s\r\n"
        "%s%s%s"
        "Content-Length: 0\r\n"
        "\r\n",
        t->host, t->port,
        t->host, t->port, t->branch,
        t->username ? t->username : "anonymous", t->host, (unsigned long long)(now ^ 0x12345678),
        t->username ? t->username : "anonymous", t->host,
        t->call_id,
        t->cseq,
        t->username ? t->username : "anonymous", t->host, t->port,
        TRUNK_REG_DEFAULT_EXPIRY,
        UPBX_VERSION_STR,
        auth_header[0] ? auth_header : "",
        auth_header[0] ? "\r\n" : "",
        auth_header[0] ? "" : ""
    );
    
    return len;
}

static int send_register(trunk_reg_t *t, const char *realm, const char *nonce) {
    if (t->fd < 0) return -1;
    
    char buf[2048];
    int len = build_register(t, buf, sizeof(buf), realm, nonce);
    if (len < 0 || (size_t)len >= sizeof(buf)) return -1;
    
    ssize_t sent = sendto(t->fd, buf, (size_t)len, 0,
                          (struct sockaddr *)&t->remote_addr, t->remote_addr_len);
    if (sent != len) {
        log_error("trunk %s: sendto failed: %s", t->name, strerror(errno));
        return -1;
    }
    
    t->cseq++;
    
    log_debug("trunk %s: sent REGISTER", t->name);
    return 0;
}

static int parse_www_authenticate(const char *value, size_t value_len,
                                   char *realm, size_t realm_size,
                                   char *nonce, size_t nonce_size) {
    if (!value || value_len == 0) return -1;
    
    realm[0] = nonce[0] = '\0';

    const char *p = value;
    const char *end = value + value_len;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == ',')) p++;
        if (p >= end) break;

        const char *eq = strchr(p, '=');
        if (!eq || eq >= end) break;

        size_t key_len = (size_t)(eq - p);
        const char *val_start = eq + 1;

        while (val_start < end && *val_start == ' ') val_start++;
        if (val_start >= end) break;

        const char *val_end;
        if (*val_start == '"') {
            val_start++;
            val_end = strchr(val_start, '"');
            if (!val_end || val_end >= end) break;
        } else {
            val_end = val_start;
            while (val_end < end && *val_end != ',' && *val_end != ' ') val_end++;
        }

        size_t val_len = (size_t)(val_end - val_start);

        if (key_len == 5 && strncasecmp(p, "realm", 5) == 0) {
            size_t copy = val_len < realm_size - 1 ? val_len : realm_size - 1;
            memcpy(realm, val_start, copy);
            realm[copy] = '\0';
        } else if ((key_len == 5 && strncasecmp(p, "nonce", 5) == 0) ||
                   (key_len == 12 && strncasecmp(p, "Digest nonce", 12) == 0)) {
            size_t copy = val_len < nonce_size - 1 ? val_len : nonce_size - 1;
            memcpy(nonce, val_start, copy);
            nonce[copy] = '\0';
        }

        p = val_end + 1;
    }

    return (realm[0] && nonce[0]) ? 0 : -1;
}

static void handle_response(trunk_reg_t *t, int64_t timestamp) {
    time_t now = (time_t)(timestamp / 1000);
    sip_message_t msg;
    memset(&msg, 0, sizeof(msg));
    
    if (sip_message_parse(t->recv_buf, (size_t)t->recv_len, &msg) != 0) {
        log_warn("trunk %s: failed to parse response", t->name);
        return;
    }
    
    if (sip_is_request(&msg)) {
        sip_message_free(&msg);
        return;
    }
    
    log_debug("trunk %s: received response %d", t->name, msg.status_code);
    
    if (msg.status_code == 200) {
        t->expires_at = timestamp + TRUNK_REG_DEFAULT_EXPIRY;
        t->retry_at = t->expires_at - TRUNK_REG_REFRESH_BEFORE;
        log_info("trunk %s: registered, expires in %d ms", t->name, TRUNK_REG_DEFAULT_EXPIRY);
    } else if (msg.status_code == 401) {
        size_t auth_len;
        const char *auth = sip_message_header_get(&msg, "WWW-Authenticate", &auth_len);
        if (auth && auth_len > 0) {
            char realm[256], nonce[256];
            if (parse_www_authenticate(auth, auth_len, realm, sizeof(realm),
                                       nonce, sizeof(nonce)) == 0) {
                log_debug("trunk %s: got 401, sending REGISTER with auth", t->name);
                send_register(t, realm, nonce);
            }
        }
    }
    
    sip_message_free(&msg);
}

PT_THREAD(trunk_reg_pt(struct pt *pt, int64_t now, struct pt_task *task)) {
    trunk_reg_t *t = task->udata;
    log_trace("trunk_reg_pt: entry for %s", t->name);
    struct addrinfo hints, *res = NULL;
    char port_str[16];
    int gai_ret;
    int fds[3];

    PT_BEGIN(pt);

    t->fd = -1;
    t->cseq = 1;
    t->expires_at = 0;
    t->retry_at = 0;
    t->refresh_requested = false;

    generate_call_id(t);
    generate_branch(t);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    snprintf(port_str, sizeof(port_str), "%d", t->port);

    gai_ret = getaddrinfo(t->host, port_str, &hints, &res);
    if (gai_ret != 0 || !res) {
        log_error("trunk %s: DNS lookup failed for %s: %s", t->name, t->host, gai_strerror(gai_ret));
        PT_EXIT(pt);
    }

    t->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (t->fd < 0) {
        log_error("trunk %s: socket failed: %s", t->name, strerror(errno));
        freeaddrinfo(res);
        PT_EXIT(pt);
    }

    set_socket_nonblocking(t->fd, 1);

    memcpy(&t->remote_addr, res->ai_addr, res->ai_addrlen);
    t->remote_addr_len = res->ai_addrlen;
    freeaddrinfo(res);

    log_info("trunk %s: starting registration to %s:%d", t->name, t->host, t->port);

    send_register(t, NULL, NULL);
    t->retry_at = now + TRUNK_REG_RETRY_INTERVAL;

    for (;;) {
        if (t->refresh_requested) {
            t->refresh_requested = false;
            send_register(t, NULL, NULL);
            t->retry_at = now + TRUNK_REG_RETRY_INTERVAL;
        } else if (t->retry_at > 0 && now >= t->retry_at) {
            send_register(t, NULL, NULL);
            t->retry_at = now + TRUNK_REG_RETRY_INTERVAL;
        }

        fds[0] = 1;
        fds[1] = t->fd;
        t->ready_fds = NULL;

        PT_WAIT_UNTIL(pt, domain_schedmod_has_data(fds, &t->ready_fds) > 0 || t->refresh_requested);

        if (t->ready_fds && t->ready_fds[0] > 0) {
            for (int i = 1; i <= t->ready_fds[0]; i++) {
                if (t->ready_fds[i] == t->fd) {
                    t->from_len = sizeof(t->from_addr);
                    t->recv_len = recvfrom(t->fd, t->recv_buf, sizeof(t->recv_buf) - 1, 0,
                                 (struct sockaddr *)&t->from_addr, &t->from_len);
                    if (t->recv_len > 0) {
                        t->recv_buf[t->recv_len] = '\0';
                        handle_response(t, now);
                    }
                }
            }
        }
        if (t->ready_fds) {
            free(t->ready_fds);
            t->ready_fds = NULL;
        }
    }

    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }

    PT_END(pt);
}

void trunk_reg_start_all(void) {
    if (!global_cfg) {
        log_warn("trunk_reg: no config loaded");
        return;
    }

    trunk_reg_stop_all();

    if (global_cfg->type != RESPT_ARRAY) {
        log_warn("trunk_reg: config is not an array");
        return;
    }

    for (size_t i = 0; i + 1 < global_cfg->u.arr.n; i += 2) {
        if (global_cfg->u.arr.elem[i].type != RESPT_BULK) continue;
        const char *key = global_cfg->u.arr.elem[i].u.s;
        if (!key || strncmp(key, "trunk:", 6) != 0) continue;
        
        if (global_cfg->u.arr.elem[i+1].type != RESPT_ARRAY) continue;
        resp_object *sec = &global_cfg->u.arr.elem[i+1];

        const char *name = key + 6;
        const char *address = NULL;
        const char *username = NULL;
        const char *password = NULL;
        const char *did = NULL;

        for (size_t j = 0; j + 1 < sec->u.arr.n; j += 2) {
            if (sec->u.arr.elem[j].type != RESPT_BULK) continue;
            const char *k = sec->u.arr.elem[j].u.s;
            if (!k) continue;
            if (sec->u.arr.elem[j+1].type != RESPT_BULK) continue;
            const char *v = sec->u.arr.elem[j+1].u.s;
            if (!v) continue;

            if (strcmp(k, "address") == 0) address = v;
            else if (strcmp(k, "username") == 0) username = v;
            else if (strcmp(k, "password") == 0) password = v;
            else if (strcmp(k, "did") == 0) did = v;
        }

        if (!address) {
            log_warn("trunk_reg: skipping trunk %s - missing address", name);
            continue;
        }

        if (trunk_count >= TRUNK_REG_MAX_TRUNKS) {
            log_error("trunk_reg: max trunks reached");
            break;
        }

        trunk_reg_t *t = calloc(1, sizeof(*t));
        if (!t) {
            log_error("trunk_reg: calloc failed");
            break;
        }

        t->name = strdup(name);
        t->address = strdup(address);
        t->host = malloc(256);
        t->fd = -1;
        t->ready_fds = NULL;

        if (parse_address(address, t->host, 256, &t->port) != 0) {
            log_error("trunk_reg: failed to parse address '%s' for trunk '%s'", address, name);
            trunk_free(t);
            continue;
        }

        t->username = username ? strdup(username) : NULL;
        t->password = password ? strdup(password) : NULL;
        t->did = did ? strdup(did) : NULL;

        trunks[trunk_count++] = t;

        domain_schedmod_pt_create(trunk_reg_pt, t);
        log_info("trunk_reg: started protothread for trunk '%s' -> %s:%d", 
                 t->name, t->host, t->port);
    }

    log_info("trunk_reg: started %zu trunk registration(s)", trunk_count);
}

void trunk_reg_stop_all(void) {
    for (size_t i = 0; i < trunk_count; i++) {
        trunk_free(trunks[i]);
        trunks[i] = NULL;
    }
    trunk_count = 0;
    log_info("trunk_reg: stopped all registrations");
}

trunk_reg_t *trunk_reg_find(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < trunk_count; i++) {
        if (trunks[i] && trunks[i]->name && strcmp(trunks[i]->name, name) == 0) {
            return trunks[i];
        }
    }
    return NULL;
}

trunk_reg_t **trunk_reg_list(size_t *count) {
    *count = trunk_count;
    return trunks;
}

void trunk_reg_refresh(const char *name) {
    trunk_reg_t *t = trunk_reg_find(name);
    if (t) {
        t->refresh_requested = true;
        log_debug("trunk_reg: refresh requested for '%s'", name);
    }
}

bool trunk_reg_is_registered(const char *name) {
    trunk_reg_t *t = trunk_reg_find(name);
    if (!t) return false;
    time_t now = time(NULL);
    return t->expires_at > 0 && now < t->expires_at;
}

time_t trunk_reg_get_expires_at(const char *name) {
    trunk_reg_t *t = trunk_reg_find(name);
    return t ? t->expires_at : 0;
}
