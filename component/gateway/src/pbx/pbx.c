#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pbx/pbx.h"
#include "sip/parser.h"
#include "sip/message.h"
#include "sdp/sdp.h"
#include "md5/md5.h"
#include "backbone/backbone.h"
#include "rtp/rtp.h"
#include "config/config.h"
#include "finwo/scheduler.h"
#include "rxi/log.h"
#include "registration/registration.h"

#define MAX_EXPIRY   300
#define DEFAULT_EXPIRY 60
#define NONCE_WINDOW 10
#define BUSY_RETRY_SEC 30
#define CLEANUP_INTERVAL 5

/* ── helpers ─────────────────────────────────────────────────── */

static void generate_hex_id(char *out, size_t len) {
    static const char hex[] = "0123456789abcdef";
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { out[0] = '\0'; return; }
    size_t need = (len - 1) / 2;
    uint8_t buf[32];
    if (need > 32) need = 32;
    fread(buf, 1, need, f);
    fclose(f);
    for (size_t i = 0; i < need && i * 2 + 1 < len; i++) {
        out[i * 2]     = hex[(buf[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[buf[i] & 0xf];
    }
    out[need * 2] = '\0';
}

static char *addr_to_str(struct sockaddr_storage *ss) {
    char ip[INET6_ADDRSTRLEN];
    int port;
    if (ss->ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)ss;
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
        port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip));
        port = ntohs(s->sin6_port);
    }
    char *buf = malloc(INET6_ADDRSTRLEN + 8);
    snprintf(buf, INET6_ADDRSTRLEN + 8, "%s:%d", ip, port);
    return buf;
}

static socklen_t get_addrlen(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) return sizeof(struct sockaddr_in);
    return sizeof(struct sockaddr_in6);
}

static const char *sdp_addr_family(const char *ip) {
    if (!ip) return "IP4";
    if (strchr(ip, ':')) return "IP6";
    return "IP4";
}

static void send_sip(int fd, struct sockaddr_storage *dst,
                     const char *data, int len) {
    sendto(fd, data, (size_t)len, 0,
           (struct sockaddr *)dst, get_addrlen(dst));
}

/* ── extension lookup by source ──────────────────────────────── */

static int addrs_same_ip(struct sockaddr_storage *a, struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        struct sockaddr_in *a4 = (struct sockaddr_in *)a;
        struct sockaddr_in *b4 = (struct sockaddr_in *)b;
        return a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    } else if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)b;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
    }
    return 0;
}

static struct gw_ext *find_ext_by_src(struct gw_config *cfg, struct sockaddr_storage *src) {
    for (struct gw_ext *e = cfg->extensions; e; e = e->next) {
        if (e->registered && memcmp(&e->remote_addr, src, sizeof(*src)) == 0)
            return e;
    }
    return NULL;
}

/* ── call lookup ─────────────────────────────────────────────── */

struct pbx_call *pbx_find_by_sip_id(struct pbx_state *s, const char *sip_call_id) {
    for (struct pbx_call *c = s->calls; c; c = c->next) {
        if (c->sip_call_id && strcmp(c->sip_call_id, sip_call_id) == 0) return c;
    }
    return NULL;
}

struct pbx_call *pbx_find_by_backbone_id(struct pbx_state *s, const char *bb_call_id) {
    for (struct pbx_call *c = s->calls; c; c = c->next) {
        if (strcmp(c->backbone_call_id, bb_call_id) == 0) return c;
    }
    return NULL;
}

static struct pbx_call *pbx_find_by_branch_sip_id(struct pbx_state *s, const char *sip_id) {
    for (struct pbx_call *c = s->calls; c; c = c->next) {
        for (struct fork_branch *b = c->branches; b; b = b->next) {
            if (b->sip_call_id && strcmp(b->sip_call_id, sip_id) == 0) return c;
        }
    }
    return NULL;
}

/* ── call cleanup ────────────────────────────────────────────── */

static void free_branches(struct fork_branch *b) {
    while (b) {
        struct fork_branch *next = b->next;
        free(b->sip_call_id);
        rtp_free(b->rtp);
        free(b);
        b = next;
    }
}

static void pbx_call_free(struct pbx_call *call) {
    free(call->sip_call_id);
    free(call->caller_ext);
    free(call->callee_did);
    free(call->caller_via);
    free(call->caller_from);
    free(call->caller_to);
    free(call->caller_contact);
    free(call->callee_from);
    free(call->callee_to);
    rtp_free(call->rtp_caller);
    rtp_free(call->rtp_callee);
    free_branches(call->branches);
    for (int i = 0; i < call->tag_count; i++) {
        free(call->tags[i].name);
        free(call->tags[i].value);
    }
    free(call->tags);
    free(call);
}

void pbx_call_remove(struct pbx_state *s, struct pbx_call *call) {
    struct pbx_call **prev = &s->calls;
    while (*prev && *prev != call) prev = &(*prev)->next;
    if (*prev == call) *prev = call->next;
    pbx_call_free(call);
}

/* ── REGISTER handler ────────────────────────────────────────── */

static void handle_register(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                            struct sip_msg *msg) {
    char *ext_num = sip_extract_uri_user(msg->to);
    if (!ext_num) {
        char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL, 0);
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        return;
    }

    struct gw_ext *ext = gw_config_find_ext(ps->config, ext_num);
    if (!ext) {
        char *resp = sip_build_response(404, "Not Found", msg, NULL, NULL, 0);
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        free(ext_num);
        return;
    }

    /* Detect pbx_addr from request-uri */
    char *pbx_addr = sip_extract_uri_host(msg->uri);
    if (pbx_addr) {
        free(ext->pbx_addr);
        ext->pbx_addr = strdup(pbx_addr);
        free(pbx_addr);
    }

    /* Check for unregister */
    if (msg->expires == 0) {
        ext->registered = 0;
        memset(&ext->remote_addr, 0, sizeof(ext->remote_addr));
        free(ext->contact);
        ext->contact = NULL;
        ext->expires = 0;
        registration_delete(ps->config->data_dir, ext->extension);
        log_info("pbx: extension %s unregistered", ext_num);
        char *resp = sip_build_response(200, "OK", msg, NULL, NULL, 0);
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        free(ext_num);
        return;
    }

    /* No auth header → send 401 challenge */
    if (!msg->authorization) {
        char nonce[32];
        snprintf(nonce, sizeof(nonce), "%ld", (long)time(NULL));
        char *resp = sip_build_401(msg, nonce, "upbx");
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        free(ext_num);
        return;
    }

    /* Parse auth header */
    struct sip_auth *auth = sip_parse_auth(msg->authorization);
    if (!auth || !auth->nonce || !auth->response || !auth->uri) {
        char nonce[32];
        snprintf(nonce, sizeof(nonce), "%ld", (long)time(NULL));
        char *resp = sip_build_401(msg, nonce, "upbx");
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        sip_auth_free(auth);
        free(ext_num);
        return;
    }

    /* Validate nonce */
    long nonce_val = atol(auth->nonce);
    long now = time(NULL);
    if (nonce_val < now - NONCE_WINDOW || nonce_val > now + NONCE_WINDOW) {
        char nonce[32];
        snprintf(nonce, sizeof(nonce), "%ld", (long)now);
        char *resp = sip_build_401(msg, nonce, "upbx");
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        sip_auth_free(auth);
        free(ext_num);
        return;
    }

    /* Compute expected response:
     * HA1 = MD5(ext:upbx:secret)
     * HA2 = MD5(REGISTER:auth_uri)
     * expected = MD5(HA1:nonce:HA2)
     */
    char ha1_buf[256];
    int ha1_len = snprintf(ha1_buf, sizeof(ha1_buf), "%s:upbx:%s", ext_num, ext->secret);
    uint8_t ha1_raw[16];
    gw_md5((const uint8_t *)ha1_buf, (size_t)ha1_len, ha1_raw);
    char ha1[33];
    gw_md5_hex(ha1_raw, ha1);

    char ha2_buf[512];
    int ha2_len = snprintf(ha2_buf, sizeof(ha2_buf), "REGISTER:%s", auth->uri);
    uint8_t ha2_raw[16];
    gw_md5((const uint8_t *)ha2_buf, (size_t)ha2_len, ha2_raw);
    char ha2[33];
    gw_md5_hex(ha2_raw, ha2);

    char resp_buf[512];
    int resp_len = snprintf(resp_buf, sizeof(resp_buf), "%s:%s:%s", ha1, auth->nonce, ha2);
    uint8_t resp_raw[16];
    gw_md5((const uint8_t *)resp_buf, (size_t)resp_len, resp_raw);
    char expected[33];
    gw_md5_hex(resp_raw, expected);

    if (strcmp(expected, auth->response) != 0) {
        log_warn("pbx: auth failed for extension %s", ext_num);
        char nonce[32];
        snprintf(nonce, sizeof(nonce), "%ld", (long)now);
        char *resp = sip_build_401(msg, nonce, "upbx");
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        sip_auth_free(auth);
        free(ext_num);
        return;
    }

    /* Auth succeeded */
    ext->remote_addr = *src;
    ext->sip_fd = fd;
    if (msg->contact) {
        free(ext->contact);
        ext->contact = strdup(msg->contact);
    }
    int expiry = DEFAULT_EXPIRY;
    if (msg->expires > 0) {
        expiry = msg->expires;
        if (expiry > MAX_EXPIRY) expiry = MAX_EXPIRY;
    }
    ext->expires = time(NULL) + expiry;
    ext->registered = 1;

    /* Save registration to disk */
    registration_save(ps->config->data_dir, ext->extension,
                      &ext->remote_addr,
                      msg->contact ? msg->contact : "",
                      ext->pbx_addr ? ext->pbx_addr : "",
                      ext->expires);

    log_info("pbx: extension %s registered", ext_num);

    char extra[128];
    snprintf(extra, sizeof(extra), "Expires: %d\r\n", expiry);
    char *resp = sip_build_response(200, "OK", msg, extra, NULL, 0);
    send_sip(fd, src, resp, (int)strlen(resp));
    free(resp);
    sip_auth_free(auth);
    free(ext_num);
}

/* ── DID rewrite ─────────────────────────────────────────────── */

static char *apply_rewrite(struct gw_config *cfg, const char *number) {
    regmatch_t pmatch[10];
    for (struct gw_rewrite_rule *r = cfg->rewrite_rules; r; r = r->next) {
        if (regexec(&r->compiled, number, 10, pmatch, 0) == 0) {
            /* Match found — apply replacement with backreferences */
            char result[512];
            const char *rp = r->replace_str;
            char *w = result;
            char *wend = result + sizeof(result) - 1;

            while (*rp && w < wend) {
                if (*rp == '\\' && rp[1] >= '1' && rp[1] <= '9') {
                    int idx = rp[1] - '0';
                    if (pmatch[idx].rm_so >= 0) {
                        int slen = pmatch[idx].rm_eo - pmatch[idx].rm_so;
                        if (w + slen <= wend) {
                            memcpy(w, number + pmatch[idx].rm_so, slen);
                            w += slen;
                        }
                    }
                    rp += 2;
                } else {
                    *w++ = *rp++;
                }
            }
            *w = '\0';
            return strdup(result);
        }
    }
    return strdup(number);
}

/* ── SIP INVITE handler ──────────────────────────────────────── */

static void send_trying(int fd, struct pbx_state *ps, struct sockaddr_storage *dst, struct sip_msg *msg) {
    char *resp = sip_build_response(100, "Trying", msg, NULL, NULL, 0);
    send_sip(fd, dst, resp, (int)strlen(resp));
    free(resp);
}

static void ext_to_ext(int fd, struct pbx_state *ps, struct sockaddr_storage *caller_addr,
                       struct gw_ext *caller_ext, struct gw_ext *callee_ext,
                       struct sip_msg *msg) {
    if (!callee_ext->registered) {
        char *resp = sip_build_response(480, "Temporarily Unavailable", msg, NULL, NULL, 0);
        send_sip(fd, caller_addr, resp, (int)strlen(resp));
        free(resp);
        return;
    }

    /* Allocate two RTP pairs */
    struct rtp_pair *rtp_a = rtp_alloc(&ps->rtp_ctx);
    struct rtp_pair *rtp_b = rtp_alloc(&ps->rtp_ctx);
    if (!rtp_a || !rtp_b) {
        char *resp = sip_build_response(500, "Server Internal Error", msg, NULL, NULL, 0);
        send_sip(fd, caller_addr, resp, (int)strlen(resp));
        free(resp);
        rtp_free(rtp_a);
        rtp_free(rtp_b);
        return;
    }
    rtp_a->peer = rtp_b;
    rtp_b->peer = rtp_a;

    /* Rewrite caller's SDP to point to rtp_a port */
    char *new_sdp = NULL;
    int new_sdp_len = 0;
    if (msg->body && msg->body_len > 0 && caller_ext->pbx_addr) {
        new_sdp = sdp_rewrite(msg->body, msg->body_len, caller_ext->pbx_addr, rtp_a->port, &new_sdp_len);
    }

    /* Create call */
    struct pbx_call *call = calloc(1, sizeof(struct pbx_call));
    call->sip_call_id = strdup(msg->call_id);
    call->caller_addr = *caller_addr;
    call->caller_ext = strdup(caller_ext->extension);
    call->callee_did = strdup(callee_ext->extension);
    call->cseq_num = msg->cseq_num;
    call->rtp_caller = rtp_a;
    call->rtp_callee = rtp_b;
    call->is_backbone_call = 0;
    call->state = CALL_PENDING;

    /* Store caller's original headers for building responses back */
    if (msg->via)     call->caller_via     = strdup(msg->via);
    if (msg->from)    call->caller_from    = strdup(msg->from);
    if (msg->contact) call->caller_contact = strdup(msg->contact);

    /* Generate gateway to-tag and build caller_to with it */
    generate_hex_id(call->gw_tag, sizeof(call->gw_tag));
    {
        /* Append ;tag=<gw_tag> to caller's To header */
        const char *orig_to = msg->to ? msg->to : "";
        size_t tlen = strlen(orig_to) + 6 + strlen(call->gw_tag) + 1;
        call->caller_to = malloc(tlen);
        snprintf(call->caller_to, tlen, "%s;tag=%s", orig_to, call->gw_tag);
    }

    call->next = ps->calls;
    ps->calls = call;

    /* Build INVITE for callee with callee's pbx_addr and rtp_b port */
    char callee_sdp[4096] = "";
    int callee_sdp_len = 0;
    if (new_sdp && callee_ext->pbx_addr) {
        char *callee_rewrite = sdp_rewrite(msg->body, msg->body_len, callee_ext->pbx_addr, rtp_b->port, &callee_sdp_len);
        if (callee_rewrite) {
            if (callee_sdp_len < (int)sizeof(callee_sdp)) {
                memcpy(callee_sdp, callee_rewrite, callee_sdp_len);
            }
            free(callee_rewrite);
        }
    }

    char cseq_method[256];
    snprintf(cseq_method, sizeof(cseq_method), "%d INVITE", msg->cseq_num + 1);

    char invite[4096];
    int ilen = snprintf(invite, sizeof(invite),
        "INVITE sip:%s@%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
        "From: %s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %s\r\n"
        "Contact: <sip:gw@%s>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        callee_ext->extension, callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
        callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0", call->backbone_call_id,
        msg->from ? msg->from : "",
        callee_ext->extension, callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
        msg->call_id,
        cseq_method,
        callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
        callee_sdp_len);

    if (ilen > 0 && callee_sdp_len > 0 && ilen + callee_sdp_len < (int)sizeof(invite)) {
        memcpy(invite + ilen, callee_sdp, callee_sdp_len);
        ilen += callee_sdp_len;
    }

    send_sip(callee_ext->sip_fd, &callee_ext->remote_addr, invite, ilen);
    free(new_sdp);
}

static void ext_to_backbone(struct pbx_state *ps, struct sockaddr_storage *caller_addr,
                            struct gw_ext *caller_ext, const char *dialed,
                            struct sip_msg *msg) {
    if (!ps->backbone || ps->backbone->phase != BACKBONE_CONNECTED) {
        log_warn("pbx: ext_to_backbone: backbone not connected, sending 503");
        char *resp = sip_build_response(503, "Service Unavailable", msg, NULL, NULL, 0);
        send_sip(caller_ext->sip_fd, caller_addr, resp, (int)strlen(resp));
        free(resp);
        return;
    }

    /* Apply rewrite rules */
    char *rewritten = apply_rewrite(ps->config, dialed);

    /* Allocate one RTP pair */
    struct rtp_pair *rtp = rtp_alloc(&ps->rtp_ctx);
    if (!rtp) {
        log_error("pbx: ext_to_backbone: RTP allocation failed, sending 500");
        char *resp = sip_build_response(500, "Server Internal Error", msg, NULL, NULL, 0);
        send_sip(caller_ext->sip_fd, caller_addr, resp, (int)strlen(resp));
        free(resp);
        free(rewritten);
        return;
    }
    rtp->is_backbone_dir = 1;
    rtp->backbone = ps->backbone;

    log_info("pbx: allocated RTP port %d fd %d for ext %s -> backbone", rtp->port, rtp->fd, caller_ext->extension);

    /* Use extension's Call-ID for backbone */
    struct pbx_call *call = calloc(1, sizeof(struct pbx_call));
    call->sip_call_id = strdup(msg->call_id);
    strncpy(call->backbone_call_id, msg->call_id, sizeof(call->backbone_call_id) - 1);
    strncpy(rtp->call_id, call->backbone_call_id, sizeof(rtp->call_id) - 1);

    call->caller_addr = *caller_addr;
    call->caller_ext = strdup(caller_ext->extension);
    call->callee_did = rewritten;
    call->cseq_num = msg->cseq_num;
    call->rtp_caller = rtp;
    call->is_backbone_call = 1;
    call->state = CALL_PENDING;

    /* Store caller's original headers for building responses back */
    if (msg->via)     call->caller_via     = strdup(msg->via);
    if (msg->from)    call->caller_from    = strdup(msg->from);
    if (msg->contact) call->caller_contact = strdup(msg->contact);

    /* Generate gateway to-tag and build caller_to with it */
    generate_hex_id(call->gw_tag, sizeof(call->gw_tag));
    {
        const char *orig_to = msg->to ? msg->to : "";
        size_t tlen = strlen(orig_to) + 6 + strlen(call->gw_tag) + 1;
        call->caller_to = malloc(tlen);
        snprintf(call->caller_to, tlen, "%s;tag=%s", orig_to, call->gw_tag);
    }
    call->next = ps->calls;
    ps->calls = call;

    /* Parse phone's SDP for codec tags */
    char *codec_tags = NULL;
    if (msg->body && msg->body_len > 0 && caller_ext->pbx_addr) {
        struct sdp_info *sdp = sdp_parse(msg->body, msg->body_len);
        if (sdp && sdp->codec_count > 0) {
            codec_tags = codec_tags_to_string(sdp->codecs, sdp->codec_count);
            /* Rewrite SDP to point to our RTP port */
            char *new_sdp = sdp_rewrite(msg->body, msg->body_len, caller_ext->pbx_addr, rtp->port, NULL);
            free(new_sdp);
        } else {
            char *new_sdp = sdp_rewrite(msg->body, msg->body_len, caller_ext->pbx_addr, rtp->port, NULL);
            free(new_sdp);
        }
        sdp_free(sdp);
    }

    /* Send invite to backbone with tags */
    {
        char tags[1024];
        tags[0] = '\0';
        int pos = 0;
        if (ps->backbone && ps->backbone->current && ps->backbone->current->username) {
            pos += snprintf(tags + pos, sizeof(tags) - pos, "pbx=%s",
                            ps->backbone->current->username);
        }
        if (caller_ext && caller_ext->extension) {
            if (pos > 0 && pos < (int)sizeof(tags) - 1) tags[pos++] = ' ';
            pos += snprintf(tags + pos, sizeof(tags) - pos, "src-ext=%s",
                            caller_ext->extension);
        }
        if (dialed) {
            if (pos > 0 && pos < (int)sizeof(tags) - 1) tags[pos++] = ' ';
            pos += snprintf(tags + pos, sizeof(tags) - pos, "dialed-number=%s",
                            dialed);
        }
        if (codec_tags && codec_tags[0]) {
            if (pos > 0 && pos < (int)sizeof(tags) - 1) tags[pos++] = ' ';
            pos += snprintf(tags + pos, sizeof(tags) - pos, "%s", codec_tags);
        }
        backbone_send_invite(ps->backbone, call->backbone_call_id, rewritten, ps->config->cid, tags);
    }

    log_info("pbx: ext %s -> backbone: did=%s (rewritten from %s), call_id=%s, cid=%s",
             caller_ext->extension, rewritten, dialed, call->backbone_call_id, ps->config->cid);

    free(codec_tags);
}

static void handle_invite(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                          struct sip_msg *msg, struct gw_ext *caller_ext) {
    send_trying(fd, ps, src, msg);

    char *dialed = sip_extract_uri_user(msg->uri);
    if (!dialed) {
        char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL, 0);
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        return;
    }

    log_info("pbx: INVITE from ext %s dialing %s", caller_ext->extension, dialed);

    /* Check if dialed number matches a registered extension */
    struct gw_ext *callee_ext = NULL;
    for (struct gw_ext *e = ps->config->extensions; e; e = e->next) {
        if (e->registered && strcmp(e->extension, dialed) == 0) {
            callee_ext = e;
            break;
        }
    }

    if (callee_ext && callee_ext != caller_ext) {
        log_info("pbx: routing ext %s -> ext %s (ext-to-ext)", caller_ext->extension, dialed);
        ext_to_ext(fd, ps, src, caller_ext, callee_ext, msg);
    } else {
        log_info("pbx: routing ext %s -> backbone for %s", caller_ext->extension, dialed);
        ext_to_backbone(ps, src, caller_ext, dialed, msg);
    }

    free(dialed);
}

/* ── SIP BYE handler ─────────────────────────────────────────── */

static void handle_bye(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                       struct sip_msg *msg) {
    log_info("pbx: handle_bye call_id=%s", msg->call_id ? msg->call_id : "?");

    struct pbx_call *call = pbx_find_by_sip_id(ps, msg->call_id);
    if (!call) {
        /* Could be a branch SIP call-id */
        call = pbx_find_by_branch_sip_id(ps, msg->call_id);
    }

    char *ok = sip_build_response(200, "OK", msg, NULL, NULL, 0);
    send_sip(fd, src, ok, (int)strlen(ok));
    free(ok);

    if (!call) {
        log_warn("pbx: BYE for unknown call %s", msg->call_id ? msg->call_id : "?");
        return;
    }

    /* Log call ended with duration */
    if (call->started_at > 0) {
        int dur = (int)(time(NULL) - call->started_at);
        log_info("pbx: call %s -> %s ended (%ds)",
                 call->caller_ext ? call->caller_ext : "?",
                 call->callee_did ? call->callee_did : "?", dur);
    }

    if (call->is_backbone_call) {
        log_info("pbx: forwarding BYE to backbone for %s", call->backbone_call_id);
        backbone_send_bye(ps->backbone, call->backbone_call_id);
    } else {
        /* ext-to-ext: forward BYE to the other party */
        int from_caller = (memcmp(src, &call->caller_addr, sizeof(*src)) == 0);
        struct gw_ext *other_ext = NULL;

        if (from_caller) {
            /* Caller hung up → send BYE to callee */
            other_ext = gw_config_find_ext(ps->config, call->callee_did);
        } else {
            /* Callee hung up → send BYE to caller */
            other_ext = gw_config_find_ext(ps->config, call->caller_ext);
        }

        if (other_ext && other_ext->registered) {
            const char *bye_from;
            const char *bye_to;

            if (from_caller) {
                /* Caller hung up → BYE to callee.
                 * Gateway is UAC in callee dialog, so From=callee_from, To=callee_to */
                bye_from = call->callee_from ? call->callee_from : "";
                bye_to   = call->callee_to   ? call->callee_to   : "";
            } else {
                /* Callee hung up → BYE to caller.
                 * Gateway is UAS in caller dialog, so From=caller_to (gw side), To=caller_from */
                bye_from = call->caller_to   ? call->caller_to   : "";
                bye_to   = call->caller_from ? call->caller_from : "";
            }

            char bye[1024];
            int blen = snprintf(bye, sizeof(bye),
                "BYE sip:%s@%s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bKgwbye%s\r\n"
                "From: %s\r\n"
                "To: %s\r\n"
                "Call-ID: %s\r\n"
                "CSeq: %d BYE\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                other_ext->extension,
                other_ext->pbx_addr ? other_ext->pbx_addr : "0.0.0.0",
                other_ext->pbx_addr ? other_ext->pbx_addr : "0.0.0.0",
                call->sip_call_id,
                bye_from,
                bye_to,
                call->sip_call_id,
                call->cseq_num + 2);
            send_sip(other_ext->sip_fd, &other_ext->remote_addr, bye, blen);
        }
    }

    pbx_call_remove(ps, call);
}

/* ── SIP CANCEL handler ──────────────────────────────────────── */

static void handle_cancel(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                          struct sip_msg *msg) {
    char *ok = sip_build_response(200, "OK", msg, NULL, NULL, 0);
    send_sip(fd, src, ok, (int)strlen(ok));
    free(ok);

    struct pbx_call *call = pbx_find_by_sip_id(ps, msg->call_id);
    if (!call) call = pbx_find_by_branch_sip_id(ps, msg->call_id);
    if (!call) return;

    /* Send CANCEL to all pending branches (backbone→ext) */
    for (struct fork_branch *b = call->branches; b; b = b->next) {
        if (!b->answered && !b->finished) {
            char cancel[512];
            int clen = snprintf(cancel, sizeof(cancel),
                "CANCEL sip:%s@%s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
                "From: <sip:gw@pbx>\r\n"
                "To: <sip:%s@%s>\r\n"
                "Call-ID: %s\r\n"
                "CSeq: 1 CANCEL\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                b->ext->extension, b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0", b->sip_call_id,
                b->ext->extension, b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                b->sip_call_id);
            send_sip(fd, &b->ext->remote_addr, cancel, clen);
            b->finished = 1;
        }
    }

    /* ext-to-ext: forward CANCEL to callee */
    if (!call->is_backbone_call) {
        struct gw_ext *callee_ext = gw_config_find_ext(ps->config, call->callee_did);
        if (callee_ext && callee_ext->registered) {
            char cancel[1024];
            int clen = snprintf(cancel, sizeof(cancel),
                "CANCEL sip:%s@%s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
                "From: %s\r\n"
                "To: <sip:%s@%s>\r\n"
                "Call-ID: %s\r\n"
                "CSeq: %d CANCEL\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                callee_ext->extension,
                callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
                callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
                call->backbone_call_id,
                call->caller_from ? call->caller_from : "",
                callee_ext->extension,
                callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
                call->sip_call_id,
                call->cseq_num + 1);
            send_sip(callee_ext->sip_fd, &callee_ext->remote_addr, cancel, clen);
        }
    }

    if (call->is_backbone_call) {
        backbone_send_cancel(ps->backbone, call->backbone_call_id);
    }

    pbx_call_remove(ps, call);
}

/* ── SIP ACK handler ─────────────────────────────────────────── */

static void handle_ack(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                       struct sip_msg *msg) {
    (void)ps;
    (void)src;
    (void)msg;
    /* ACK is handled implicitly — no response needed */
}

/* ── SIP OPTIONS handler ─────────────────────────────────────── */

static void handle_options(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                           struct sip_msg *msg) {
    char *resp = sip_build_response(200, "OK", msg, NULL, NULL, 0);
    send_sip(fd, src, resp, (int)strlen(resp));
    free(resp);
}

/* ── SIP response handler (from extensions) ──────────────────── */

static void handle_sip_response(int fd, struct pbx_state *ps, struct sockaddr_storage *src,
                                struct sip_msg *msg) {
    (void)src;

    /* Find the call — could be a direct call or a fork branch */
    struct pbx_call *call = pbx_find_by_sip_id(ps, msg->call_id);
    struct fork_branch *branch = NULL;

    if (!call) {
        /* Check if this is a fork branch response */
        call = pbx_find_by_branch_sip_id(ps, msg->call_id);
        if (call) {
            for (struct fork_branch *b = call->branches; b; b = b->next) {
                if (b->sip_call_id && strcmp(b->sip_call_id, msg->call_id) == 0) {
                    branch = b;
                    break;
                }
            }
        }
    }

    if (!call) return;

    int code = msg->status_code;

    /* Handle ext-to-ext responses */
    if (!call->is_backbone_call && !branch) {
        struct gw_ext *caller_ext = gw_config_find_ext(ps->config, call->caller_ext);
        struct gw_ext *callee_ext = gw_config_find_ext(ps->config, call->callee_did);
        int caller_fd = caller_ext ? caller_ext->sip_fd : fd;

        /* Callee's response to our ext-to-ext INVITE */
        if (code == 100) {
            /* 100 Trying — absorb, don't forward */
            return;
        } else if (code == 180) {
            /* Forward ringing to caller using caller's original headers */
            char resp[2048];
            int rlen = snprintf(resp, sizeof(resp),
                "SIP/2.0 180 Ringing\r\n"
                "Via: %s\r\n"
                "From: %s\r\n"
                "To: %s\r\n"
                "Call-ID: %s\r\n"
                "CSeq: %d INVITE\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                call->caller_via ? call->caller_via : "",
                call->caller_from ? call->caller_from : "",
                call->caller_to ? call->caller_to : "",
                call->sip_call_id,
                call->cseq_num);
            send_sip(caller_fd, &call->caller_addr, resp, rlen);
            call->state = CALL_RINGING;
        } else if (code == 200) {
            if (call->state == CALL_ACTIVE) {
                /* Already active — just re-send ACK to callee (retransmitted 200) */
            } else {
                call->state = CALL_ACTIVE;
                call->started_at = time(NULL);

                /* Store callee's dialog From/To (includes callee's tag) */
                free(call->callee_from);
                call->callee_from = msg->from ? strdup(msg->from) : NULL;
                free(call->callee_to);
                call->callee_to = msg->to ? strdup(msg->to) : NULL;

                log_info("pbx: call %s -> %s established",
                         call->caller_ext, call->callee_did);
            }

            /* Rewrite SDP for caller */
            char *body = NULL;
            int body_len = 0;
            if (msg->body && msg->body_len > 0 && caller_ext && caller_ext->pbx_addr) {
                body = sdp_rewrite(msg->body, msg->body_len, caller_ext->pbx_addr,
                                   call->rtp_caller->port, &body_len);
            }

            /* Build and send 200 OK to caller using caller's original headers */
            char resp[4096];
            int rlen = snprintf(resp, sizeof(resp),
                "SIP/2.0 200 OK\r\n"
                "Via: %s\r\n"
                "From: %s\r\n"
                "To: %s\r\n"
                "Call-ID: %s\r\n"
                "CSeq: %d INVITE\r\n"
                "Contact: <sip:gw@%s>\r\n"
                "%s"
                "Content-Length: %d\r\n"
                "\r\n",
                call->caller_via ? call->caller_via : "",
                call->caller_from ? call->caller_from : "",
                call->caller_to ? call->caller_to : "",
                call->sip_call_id,
                call->cseq_num,
                caller_ext && caller_ext->pbx_addr ? caller_ext->pbx_addr : "0.0.0.0",
                body_len > 0 ? "Content-Type: application/sdp\r\n" : "",
                body_len);
            if (rlen > 0 && body_len > 0 && rlen + body_len < (int)sizeof(resp)) {
                memcpy(resp + rlen, body, body_len);
                rlen += body_len;
            }
            send_sip(caller_fd, &call->caller_addr, resp, rlen);
            free(body);

            /* Send ACK to callee */
            if (callee_ext) {
                char ack[1024];
                int alen = snprintf(ack, sizeof(ack),
                    "ACK sip:%s@%s SIP/2.0\r\n"
                    "Via: SIP/2.0/UDP %s;branch=z9hG4bKgwack%s\r\n"
                    "From: %s\r\n"
                    "To: %s\r\n"
                    "Call-ID: %s\r\n"
                    "CSeq: %d ACK\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n",
                    callee_ext->extension,
                    callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
                    callee_ext->pbx_addr ? callee_ext->pbx_addr : "0.0.0.0",
                    call->sip_call_id,
                    msg->from ? msg->from : "",
                    msg->to ? msg->to : "",
                    call->sip_call_id,
                    call->cseq_num + 1);
                send_sip(callee_ext->sip_fd, &callee_ext->remote_addr, ack, alen);
            }
        } else if (code >= 400) {
            /* Forward error to caller using caller's original headers */
            char resp[2048];
            int rlen = snprintf(resp, sizeof(resp),
                "SIP/2.0 %d %s\r\n"
                "Via: %s\r\n"
                "From: %s\r\n"
                "To: %s\r\n"
                "Call-ID: %s\r\n"
                "CSeq: %d INVITE\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                code, msg->reason ? msg->reason : "Error",
                call->caller_via ? call->caller_via : "",
                call->caller_from ? call->caller_from : "",
                call->caller_to ? call->caller_to : "",
                call->sip_call_id,
                call->cseq_num);
            send_sip(caller_fd, &call->caller_addr, resp, rlen);
            pbx_call_remove(ps, call);
        }
        return;
    }

    /* Handle ext-to-backbone responses — shouldn't happen from ext side normally */
    if (call->is_backbone_call && !branch) return;

    /* Handle backbone→ext fork branch responses */
    if (!branch) return;

    if (code == 180) {
        /* First ringing → send ringing to backbone */
        if (call->state < CALL_RINGING && ps->backbone) {
            backbone_send_ringing(ps->backbone, call->backbone_call_id, "");
            call->state = CALL_RINGING;
        }
    } else if (code == 200) {
        if (call->state >= CALL_ACTIVE) {
            /* Double pickup race — send BYE to late answerer */
            char bye[512];
            int blen = snprintf(bye, sizeof(bye),
                "BYE sip:%s@%s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
                "From: <sip:gw@pbx>\r\n"
                "To: <sip:%s@%s>\r\n"
                "Call-ID: %s\r\n"
                "CSeq: 2 BYE\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                branch->ext->extension, branch->ext->pbx_addr ? branch->ext->pbx_addr : "0.0.0.0",
                branch->ext->pbx_addr ? branch->ext->pbx_addr : "0.0.0.0", branch->sip_call_id,
                branch->ext->extension, branch->ext->pbx_addr ? branch->ext->pbx_addr : "0.0.0.0",
                branch->sip_call_id);
            send_sip(fd, &branch->ext->remote_addr, bye, blen);
            return;
        }

        branch->answered = 1;
        call->state = CALL_ACTIVE;

        /* Send answer to backbone */
        backbone_send_answer(ps->backbone, call->backbone_call_id, "");

        /* Set up RTP for this branch */
        if (branch->rtp) {
            call->rtp_caller = branch->rtp;
            branch->rtp = NULL; /* ownership transferred */
        }

        /* Send ACK to answering extension */
        if (msg->contact) {
            char ack[512];
            int alen = snprintf(ack, sizeof(ack),
                "ACK %s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bKgwack%s\r\n"
                "From: <sip:gw@pbx>\r\n"
                "To: %s\r\n"
                "Call-ID: %s\r\n"
                "CSeq: 1 ACK\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                msg->contact,
                branch->ext->pbx_addr ? branch->ext->pbx_addr : "0.0.0.0",
                branch->sip_call_id,
                msg->to ? msg->to : "",
                branch->sip_call_id);
            send_sip(fd, &branch->ext->remote_addr, ack, alen);
        }

        /* Cancel all other pending branches */
        for (struct fork_branch *b = call->branches; b; b = b->next) {
            if (b != branch && !b->answered && !b->finished) {
                char cancel[512];
                int clen = snprintf(cancel, sizeof(cancel),
                    "CANCEL sip:%s@%s SIP/2.0\r\n"
                    "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
                    "From: <sip:gw@pbx>\r\n"
                    "To: <sip:%s@%s>\r\n"
                    "Call-ID: %s\r\n"
                    "CSeq: 1 CANCEL\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n",
                    b->ext->extension, b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                    b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0", b->sip_call_id,
                    b->ext->extension, b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                    b->sip_call_id);
                send_sip(fd, &b->ext->remote_addr, cancel, clen);
                b->finished = 1;
            }
        }

        log_info("pbx: call backbone -> %s to ext %s established",
                 call->backbone_call_id, branch->ext->extension);
    } else if (code == 486) {
        /* Busy — queue for retry */
        branch->busy = 1;
        branch->retry_at = time(NULL) + BUSY_RETRY_SEC;
        (void)0; /* busy, will retry */
    } else if (code >= 400) {
        /* Other failure — mark finished */
        branch->finished = 1;
    }
}

/* ── Backbone INVITE handler ─────────────────────────────────── */

void pbx_on_backbone_ringing(struct pbx_state *s, const char *call_id, const char *codec_tags) {
    struct pbx_call *call = pbx_find_by_backbone_id(s, call_id);
    if (!call) return;

    struct gw_ext *caller_ext = gw_config_find_ext(s->config, call->caller_ext);
    if (!caller_ext) return;

    /* Build SDP body from codec tags (or empty) */
    char *sdp_body = NULL;
    int sdp_len = 0;
    if (codec_tags && codec_tags[0]) {
        struct codec_tag tags[MAX_CODEC_TAGS];
        int tag_count = codec_tags_from_string(codec_tags, tags, MAX_CODEC_TAGS);
        if (tag_count > 0 && call->rtp_caller) {
            sdp_body = sdp_build_from_codecs(call->rtp_caller->port, "IP4", tags, tag_count);
            if (sdp_body) {
                /* Replace 0.0.0.0 with the address the extension registered to */
                if (caller_ext->pbx_addr) {
                    char *rewritten = sdp_rewrite(sdp_body, (int)strlen(sdp_body),
                                                  caller_ext->pbx_addr, call->rtp_caller->port, &sdp_len);
                    free(sdp_body);
                    sdp_body = rewritten;
                } else {
                    sdp_len = (int)strlen(sdp_body);
                }
            }
        }
    }

    /* Send 180 Ringing to the extension */
    char ringing[4096];
    int rlen = snprintf(ringing, sizeof(ringing),
        "SIP/2.0 180 Ringing\r\n"
        "Via: %s\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d INVITE\r\n"
        "%s"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s",
        call->caller_via ? call->caller_via : "SIP/2.0/UDP 0.0.0.0",
        call->caller_from ? call->caller_from : "<sip:unknown>",
        call->caller_to ? call->caller_to : "<sip:unknown>",
        call->sip_call_id,
        call->cseq_num,
        sdp_body ? "Content-Type: application/sdp\r\n" : "",
        sdp_len,
        sdp_body ? sdp_body : "");
    send_sip(caller_ext->sip_fd, &call->caller_addr, ringing, rlen);
    free(sdp_body);
    log_info("pbx: sent 180 Ringing to ext %s for call %s", call->caller_ext, call->backbone_call_id);
    call->state = CALL_RINGING;
}

void pbx_on_backbone_answer(struct pbx_state *s, const char *call_id, const char *codec_tags) {
    struct pbx_call *call = pbx_find_by_backbone_id(s, call_id);
    if (!call) return;

    struct gw_ext *caller_ext = gw_config_find_ext(s->config, call->caller_ext);
    if (!caller_ext) return;

    /* Build SDP body from codec tags (or empty) */
    char *sdp_body = NULL;
    int sdp_len = 0;
    if (codec_tags && codec_tags[0]) {
        struct codec_tag tags[MAX_CODEC_TAGS];
        int tag_count = codec_tags_from_string(codec_tags, tags, MAX_CODEC_TAGS);
        if (tag_count > 0 && call->rtp_caller) {
            sdp_body = sdp_build_from_codecs(call->rtp_caller->port, "IP4", tags, tag_count);
            if (sdp_body) {
                /* Replace 0.0.0.0 with the address the extension registered to */
                if (caller_ext->pbx_addr) {
                    char *rewritten = sdp_rewrite(sdp_body, (int)strlen(sdp_body),
                                                  caller_ext->pbx_addr, call->rtp_caller->port, &sdp_len);
                    free(sdp_body);
                    sdp_body = rewritten;
                } else {
                    sdp_len = (int)strlen(sdp_body);
                }
            }
        }
    }

    char ok[4096];
    int olen = snprintf(ok, sizeof(ok),
        "SIP/2.0 200 OK\r\n"
        "Via: %s\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d INVITE\r\n"
        "Contact: <sip:gw@%s>\r\n"
        "%s"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s",
        call->caller_via ? call->caller_via : "SIP/2.0/UDP 0.0.0.0",
        call->caller_from ? call->caller_from : "<sip:unknown>",
        call->caller_to ? call->caller_to : "<sip:unknown>",
        call->sip_call_id,
        call->cseq_num,
        caller_ext && caller_ext->pbx_addr ? caller_ext->pbx_addr : "0.0.0.0",
        sdp_body ? "Content-Type: application/sdp\r\n" : "",
        sdp_len,
        sdp_body ? sdp_body : "");

    free(sdp_body);

    send_sip(caller_ext->sip_fd, &call->caller_addr, ok, olen);
    log_info("pbx: sent 200 OK to ext %s for call %s", call->caller_ext, call->backbone_call_id);
    call->state = CALL_ACTIVE;
}

void pbx_on_backbone_cancel(struct pbx_state *s, const char *call_id) {
    struct pbx_call *call = pbx_find_by_backbone_id(s, call_id);
    if (!call) return;
    /* Once the call is ringing or beyond, cancel is ignored — use bye instead */
    if (call->state >= CALL_RINGING) return;
    pbx_call_remove(s, call);
}

void pbx_on_backbone_media(struct pbx_state *s, const char *call_id,
                           int stream_id, const uint8_t *data, size_t len) {
    struct pbx_call *call = pbx_find_by_backbone_id(s, call_id);
    if (!call || call->state != CALL_ACTIVE) return;
    if (!call->rtp_caller) return;

    /* Send decoded RTP to extension */
    rtp_send_to_ext(call->rtp_caller, data, len);
}

void pbx_on_backbone_bye(struct pbx_state *s, const char *call_id) {
    struct pbx_call *call = pbx_find_by_backbone_id(s, call_id);
    if (!call) return;

    struct gw_ext *caller_ext = gw_config_find_ext(s->config, call->caller_ext);

    /* Send BYE to the connected extension */
    if (call->rtp_caller && caller_ext) {
        char bye[512];
        int blen = snprintf(bye, sizeof(bye),
            "BYE sip:%s@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s;branch=z9hG4bKgwbye\r\n"
            "From: <sip:gw@pbx>\r\n"
            "To: <sip:%s@%s>\r\n"
            "Call-ID: %s\r\n"
            "CSeq: 2 BYE\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            call->caller_ext ? call->caller_ext : "?",
            "0.0.0.0",
            "0.0.0.0",
            call->caller_ext ? call->caller_ext : "?",
            "0.0.0.0",
            call->sip_call_id);
        send_sip(caller_ext->sip_fd, &call->caller_addr, bye, blen);
    }

    pbx_call_remove(s, call);
}

/* ── Backbone INVITE (incoming call from backbone) ───────────── */

/* Called by the backbone module when it receives "invite <call_id> <did> <cid> [tags...]" */
static void handle_backbone_invite(struct pbx_state *ps, const char *call_id,
                                   const char *did, const char *cid,
                                   struct gw_tag_entry *tags, int tag_count) {
    /* Check if DID matches any configured DID */
    int did_match = 0;
    for (struct gw_did *d = ps->config->dids; d; d = d->next) {
        if (strcmp(d->did, did) == 0) {
            did_match = 1;
            break;
        }
    }
    if (!did_match) {
        (void)0; /* DID not in our list */
        return;
    }

    /* Find all registered extensions */
    int n_ext = 0;
    for (struct gw_ext *e = ps->config->extensions; e; e = e->next) {
        if (e->registered) n_ext++;
    }

    if (n_ext == 0) {
        (void)0; /* no registered extensions */
        backbone_send_cancel(ps->backbone, call_id);
        return;
    }

    /* Create call */
    struct pbx_call *call = calloc(1, sizeof(struct pbx_call));
    call->backbone_call_id[0] = '\0';
    strncpy(call->backbone_call_id, call_id, sizeof(call->backbone_call_id) - 1);
    call->is_backbone_call = 1;
    call->callee_did = strdup(did);
    call->caller_ext = strdup(cid);
    call->state = CALL_PENDING;

    /* Store tags from backbone invite */
    if (tag_count > 0 && tags) {
        call->tag_count = tag_count;
        call->tags = malloc(tag_count * sizeof(struct gw_tag_entry));
        for (int i = 0; i < tag_count; i++) {
            call->tags[i].name = strdup(tags[i].name);
            call->tags[i].value = strdup(tags[i].value);
        }
    }

    call->next = ps->calls;
    ps->calls = call;

    /* Fork to all registered extensions */
    int ringing_sent = 0;
    for (struct gw_ext *e = ps->config->extensions; e; e = e->next) {
        if (!e->registered) continue;

        struct fork_branch *branch = calloc(1, sizeof(struct fork_branch));
        branch->ext = e;
        branch->sip_call_id = malloc(64);
        generate_hex_id(branch->sip_call_id, 64);
        branch->rtp = rtp_alloc(&ps->rtp_ctx);

        if (!branch->rtp) {
            free(branch->sip_call_id);
            free(branch);
            continue;
        }

        /* Build SDP offer pointing to PBX's RTP port */
        char sdp_body[512];
        int sdp_len = 0;
        if (e->pbx_addr) {
            const char *af = sdp_addr_family(e->pbx_addr);
            sdp_len = snprintf(sdp_body, sizeof(sdp_body),
                "v=0\r\n"
                "o=- 0 0 IN %s %s\r\n"
                "s=session\r\n"
                "c=IN %s %s\r\n"
                "t=0 0\r\n"
                "m=audio %d RTP/AVP 0 8 101\r\n"
                "a=rtpmap:0 PCMU/8000\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=rtpmap:101 telephone-event/8000\r\n",
                af, e->pbx_addr, af, e->pbx_addr, branch->rtp->port);
        }

        /* Send INVITE to extension */
        char invite[2048];
        int ilen = snprintf(invite, sizeof(invite),
            "INVITE sip:%s@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
            "From: <sip:%s@pbx>;tag=gw%s\r\n"
            "To: <sip:%s@%s>\r\n"
            "Call-ID: %s\r\n"
            "CSeq: 1 INVITE\r\n"
            "Contact: <sip:gw@%s>\r\n"
            "Content-Type: application/sdp\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            e->extension, e->pbx_addr ? e->pbx_addr : "0.0.0.0",
            e->pbx_addr ? e->pbx_addr : "0.0.0.0", branch->sip_call_id,
            cid, call_id,
            e->extension, e->pbx_addr ? e->pbx_addr : "0.0.0.0",
            branch->sip_call_id,
            e->pbx_addr ? e->pbx_addr : "0.0.0.0",
            sdp_len);

        if (ilen > 0 && sdp_len > 0 && ilen + sdp_len < (int)sizeof(invite)) {
            memcpy(invite + ilen, sdp_body, sdp_len);
            ilen += sdp_len;
        }

        send_sip(e->sip_fd, &e->remote_addr, invite, ilen);
        branch->invite_sent = 1;
        branch->next = call->branches;
        call->branches = branch;

        if (!ringing_sent) {
            backbone_send_ringing(ps->backbone, call_id, "");
            ringing_sent = 1;
        }
    }

    (void)call_id; (void)did; (void)cid; (void)n_ext;
}

/* Expose backbone invite for the backbone module to call */
void pbx_handle_backbone_invite(struct pbx_state *ps, const char *call_id,
                                const char *did, const char *cid,
                                struct gw_tag_entry *tags, int tag_count) {
    handle_backbone_invite(ps, call_id, did, cid, tags, tag_count);
}

/* ── Busy retry task ─────────────────────────────────────────── */

int busy_retry_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct pbx_state *ps = pt->udata;
    time_t now = time(NULL);

    for (struct pbx_call *call = ps->calls; call; call = call->next) {
        if (call->state >= CALL_ACTIVE) continue;

        for (struct fork_branch *b = call->branches; b; b = b->next) {
            if (b->busy && !b->answered && !b->finished && b->retry_at <= now && b->ext->registered) {
                /* Re-send INVITE to this busy extension */
                char *new_sip_id = malloc(64);
                generate_hex_id(new_sip_id, 64);
                free(b->sip_call_id);
                b->sip_call_id = new_sip_id;

                struct rtp_pair *new_rtp = rtp_alloc(&ps->rtp_ctx);
                if (new_rtp) {
                    rtp_free(b->rtp);
                    b->rtp = new_rtp;
                }

                char sdp_body[512];
                int sdp_len = 0;
                if (b->ext->pbx_addr && b->rtp) {
                    const char *af = sdp_addr_family(b->ext->pbx_addr);
                    sdp_len = snprintf(sdp_body, sizeof(sdp_body),
                        "v=0\r\n"
                        "o=- 0 0 IN %s %s\r\n"
                        "s=session\r\n"
                        "c=IN %s %s\r\n"
                        "t=0 0\r\n"
                        "m=audio %d RTP/AVP 0 8 101\r\n"
                        "a=rtpmap:0 PCMU/8000\r\n"
                        "a=rtpmap:8 PCMA/8000\r\n"
                        "a=rtpmap:101 telephone-event/8000\r\n",
                        af, b->ext->pbx_addr, af, b->ext->pbx_addr, b->rtp->port);
                }

                char invite[2048];
                int ilen = snprintf(invite, sizeof(invite),
                    "INVITE sip:%s@%s SIP/2.0\r\n"
                    "Via: SIP/2.0/UDP %s;branch=z9hG4bKgw%s\r\n"
                    "From: <sip:%s@pbx>;tag=gw%s\r\n"
                    "To: <sip:%s@%s>\r\n"
                    "Call-ID: %s\r\n"
                    "CSeq: 1 INVITE\r\n"
                    "Contact: <sip:gw@%s>\r\n"
                    "Content-Type: application/sdp\r\n"
                    "Content-Length: %d\r\n"
                    "\r\n",
                    b->ext->extension, b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                    b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0", b->sip_call_id,
                    call->caller_ext ? call->caller_ext : "?", call->backbone_call_id,
                    b->ext->extension, b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                    b->sip_call_id,
                    b->ext->pbx_addr ? b->ext->pbx_addr : "0.0.0.0",
                    sdp_len);

                if (ilen > 0 && sdp_len > 0 && ilen + sdp_len < (int)sizeof(invite)) {
                    memcpy(invite + ilen, sdp_body, sdp_len);
                    ilen += sdp_len;
                }

                send_sip(b->ext->sip_fd, &b->ext->remote_addr, invite, ilen);
                b->busy = 0;
                b->invite_sent = 1;
                b->retry_at = now + BUSY_RETRY_SEC;

                (void)0; /* retrying */
            }
        }
    }

    return SCHED_RUNNING;
}

/* ── Extension cleanup task ───────────────────────────────────── */

int cleanup_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct pbx_state *ps = pt->udata;

    /* Check one random registration on disk for expiry */
    if (ps->config->data_dir)
        registration_cleanup_once(ps->config->data_dir);

    return SCHED_RUNNING;
}

/* ── SIP receive task ────────────────────────────────────────── */

int sip_recv_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct pbx_state *ps = pt->udata;

    int ready_fd = sched_has_data(ps->sip_fds);
    if (ready_fd < 0) return SCHED_RUNNING;

    char buf[4096];
    struct sockaddr_storage src;
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(ready_fd, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr *)&src, &src_len);
    if (n <= 0) return SCHED_RUNNING;

    buf[n] = '\0';

    struct sip_msg *msg = sip_parse_request(buf, (int)n);
    if (!msg) return SCHED_RUNNING;

    if (msg->status_code == 0 && msg->method_str) {
        char *src_str = addr_to_str(&src);
        log_info("pbx: received %s from %s", msg->method_str, src_str);
        free(src_str);
    }

    if (msg->status_code > 0) {
        handle_sip_response(ready_fd, ps, &src, msg);
    } else {
        switch (msg->method) {
        case SIP_METHOD_REGISTER:
            handle_register(ready_fd, ps, &src, msg);
            break;
        case SIP_METHOD_OPTIONS:
            handle_options(ready_fd, ps, &src, msg);
            break;
        default: {
            /* All other methods require a registered sender.
             * Look up registration by source address on disk. */
            char *found_ext = registration_find_by_addr(ps->config->data_dir, &src);
            if (!found_ext) {
                log_warn("pbx: SIP %s from unregistered source, sending 403", msg->method_str ? msg->method_str : "?");
                char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL, 0);
                send_sip(ready_fd, &src, resp, (int)strlen(resp));
                free(resp);
                break;
            }
            /* Verify the claimed From user matches the registered extension */
            char *claimed = sip_extract_uri_user(msg->from);
            if (!claimed || strcmp(claimed, found_ext) != 0) {
                log_warn("pbx: SIP %s from %s but claims %s, sending 403",
                         msg->method_str ? msg->method_str : "?", found_ext, claimed ? claimed : "?");
                char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL, 0);
                send_sip(ready_fd, &src, resp, (int)strlen(resp));
                free(resp);
                free(claimed);
                free(found_ext);
                break;
            }
            free(claimed);

            struct gw_ext *caller_ext = gw_config_find_ext(ps->config, found_ext);
            free(found_ext);
            if (!caller_ext) {
                char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL, 0);
                send_sip(ready_fd, &src, resp, (int)strlen(resp));
                free(resp);
                break;
            }
            /* Update in-memory remote_addr for port tracking */
            caller_ext->remote_addr = src;
            caller_ext->sip_fd = ready_fd;

            switch (msg->method) {
            case SIP_METHOD_INVITE:
                handle_invite(ready_fd, ps, &src, msg, caller_ext);
                break;
            case SIP_METHOD_BYE:
                handle_bye(ready_fd, ps, &src, msg);
                break;
            case SIP_METHOD_CANCEL:
                handle_cancel(ready_fd, ps, &src, msg);
                break;
            case SIP_METHOD_ACK:
                handle_ack(ready_fd, ps, &src, msg);
                break;
            default:
                break;
            }
            break;
        }
        }
    }

    sip_msg_free(msg);
    return SCHED_RUNNING;
}

/* ── Public API ──────────────────────────────────────────────── */

struct pbx_state *pbx_create(struct gw_config *cfg) {
    struct pbx_state *ps = calloc(1, sizeof(struct pbx_state));
    if (!ps) return NULL;
    ps->config = cfg;
    ps->sip_fds = NULL;
    rtp_ctx_init(&ps->rtp_ctx, cfg->rtp_min, cfg->rtp_max);
    return ps;
}

void pbx_free(struct pbx_state *ps) {
    if (!ps) return;
    if (ps->sip_task) sched_remove(ps->sip_task);
    if (ps->busy_retry_task) sched_remove(ps->busy_retry_task);
    if (ps->cleanup_task) sched_remove(ps->cleanup_task);
    while (ps->calls) {
        struct pbx_call *next = ps->calls->next;
        pbx_call_free(ps->calls);
        ps->calls = next;
    }
    free(ps);
}
