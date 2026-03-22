#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include "trunk/trunk.h"
#include "sip/parser.h"
#include "sip/message.h"
#include "sdp/sdp.h"
#include "backbone/backbone.h"
#include "rtp/rtp.h"
#include "register/register.h"
#include "config/config.h"
#include "md5/md5.h"
#include "finwo/scheduler.h"
#include "rxi/log.h"

static void md5_hexdigest(const char *input, char *out) {
    uint8_t digest[16];
    trk_md5((const uint8_t *)input, strlen(input), digest);
    trk_md5_hex(digest, out);
}

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

static socklen_t get_addrlen(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) return sizeof(struct sockaddr_in);
    return sizeof(struct sockaddr_in6);
}

static const char *sdp_addr_family(const char *ip) {
    if (!ip) return "IP4";
    if (strchr(ip, ':')) return "IP6";
    return "IP4";
}

static void sockaddr_to_str(const struct sockaddr_storage *addr,
                            char *buf, size_t buflen) {
    if (addr->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr,
                  buf, (socklen_t)buflen);
    } else if (addr->ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr,
                  buf, (socklen_t)buflen);
    } else {
        snprintf(buf, buflen, "?");
    }
}

static int sockaddr_port(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET)
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    if (addr->ss_family == AF_INET6)
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    return 0;
}

static void send_sip(int fd, struct sockaddr_storage *dst,
                     const char *data, int len) {
    char ip[INET6_ADDRSTRLEN];
    sockaddr_to_str(dst, ip, sizeof(ip));
    log_info("trunk: >>> SIP to %s:%d fd=%d (%d bytes)\n%.*s",
             ip, sockaddr_port(dst), fd, len, len, data);
    ssize_t sent = sendto(fd, data, (size_t)len, 0,
                          (struct sockaddr *)dst, get_addrlen(dst));
    if (sent < 0) {
        log_error("trunk: sendto failed: %s (errno=%d)", strerror(errno), errno);
    } else {
        log_debug("trunk: sendto sent %zd bytes", sent);
    }
}

/* ── call lookup ─────────────────────────────────────────────── */

struct trunk_call *trunk_find_by_sip_id(struct trunk_state *s, const char *sip_call_id) {
    for (struct trunk_call *c = s->calls; c; c = c->next) {
        if (c->sip_call_id && strcmp(c->sip_call_id, sip_call_id) == 0) return c;
    }
    return NULL;
}

struct trunk_call *trunk_find_by_backbone_id(struct trunk_state *s, const char *bb_call_id) {
    for (struct trunk_call *c = s->calls; c; c = c->next) {
        if (strcmp(c->backbone_call_id, bb_call_id) == 0) return c;
    }
    return NULL;
}

/* ── call cleanup ────────────────────────────────────────────── */

static void trunk_call_free(struct trunk_call *call) {
    free(call->sip_call_id);
    free(call->trunk_did);
    free(call->trunk_cid);
    free(call->trunk_via);
    free(call->trunk_from);
    free(call->trunk_to);
    free(call->trunk_contact);
    free(call->remote_sdp_host);
    free(call->backbone_tags);
    rtp_free(call->rtp);
    free(call);
}

static void trunk_call_remove(struct trunk_state *s, struct trunk_call *call) {
    struct trunk_call **prev = &s->calls;
    while (*prev && *prev != call) prev = &(*prev)->next;
    if (*prev == call) *prev = call->next;
    trunk_call_free(call);
}

/* ── filter matching ─────────────────────────────────────────── */

static int match_tag(struct trk_filter_tag *tag, const char *tags_str) {
    const char *p = tags_str;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;

        const char *eq = strchr(p, '=');
        const char *end = eq ? eq : p;
        while (*end && *end != ' ') end++;

        size_t name_len = (size_t)(eq ? eq - p : end - p);

        if (strlen(tag->name) == name_len && memcmp(tag->name, p, name_len) == 0) {
            /* Presence-only tag: name matches, don't care about value */
            if (!tag->value) return 1;

            if (!eq) return 0; /* tag has value filter but invite tag has no value */

            const char *vstart = eq + 1;
            size_t val_len = (size_t)(end - vstart);
            char val_buf[256];
            if (val_len >= sizeof(val_buf)) val_len = sizeof(val_buf) - 1;
            memcpy(val_buf, vstart, val_len);
            val_buf[val_len] = '\0';

            if (tag->is_glob) {
                if (regexec(&tag->compiled, val_buf, 0, NULL, 0) == 0) return 1;
            } else {
                if (strcmp(tag->value, val_buf) == 0) return 1;
            }
            return 0;
        }

        p = end;
    }
    return 0;
}

static int trunk_filter_matches(struct trk_filter *filter, const char *tags_str) {
    for (int i = 0; i < filter->tag_count; i++) {
        if (!match_tag(&filter->tags[i], tags_str)) return 0;
    }
    return 1;
}

static int trunk_any_filter_matches(struct trunk_state *ts, const char *tags_str) {
    for (struct trk_filter *f = ts->config->filters; f; f = f->next) {
        if (trunk_filter_matches(f, tags_str)) return 1;
    }
    return 0;
}

/* ── SIP INVITE generation for outgoing call to trunk ────────── */

static void resend_invite_with_auth(struct trunk_state *ts, struct trunk_call *call,
                                    const char *www_auth) {
    struct trk_backbone *target = ts->config->target;
    if (!target || !target->host || !target->username || !target->password) return;

    /* Parse realm and nonce from WWW-Authenticate */
    char *realm = NULL, *nonce = NULL;

    const char *p = strstr(www_auth, "realm=\"");
    if (p) {
        p += 7;
        const char *end = strchr(p, '"');
        if (end) {
            size_t len = (size_t)(end - p);
            realm = malloc(len + 1);
            memcpy(realm, p, len);
            realm[len] = '\0';
        }
    }

    p = strstr(www_auth, "nonce=\"");
    if (p) {
        p += 7;
        const char *end = strchr(p, '"');
        if (end) {
            size_t len = (size_t)(end - p);
            nonce = malloc(len + 1);
            memcpy(nonce, p, len);
            nonce[len] = '\0';
        }
    }

    if (!realm || !nonce) {
        free(realm); free(nonce);
        return;
    }

    const char *user = target->username;
    const char *pass = target->password;
    const char *host = target->host;

    /* Digest auth: HA1 = md5(user:realm:pass) */
    char ha1_input[512];
    snprintf(ha1_input, sizeof(ha1_input), "%s:%s:%s", user, realm, pass);
    char ha1[33];
    md5_hexdigest(ha1_input, ha1);

    /* HA2 = md5(INVITE:uri) */
    char uri[256];
    snprintf(uri, sizeof(uri), "sip:%s@%s",
             call->trunk_did ? call->trunk_did : "?", host);
    char ha2_input[512];
    snprintf(ha2_input, sizeof(ha2_input), "INVITE:%s", uri);
    char ha2[33];
    md5_hexdigest(ha2_input, ha2);

    /* response = md5(HA1:nonce:HA2) */
    char resp_input[512];
    snprintf(resp_input, sizeof(resp_input), "%s:%s:%s", ha1, nonce, ha2);
    char response[33];
    md5_hexdigest(resp_input, response);

    char auth_hdr[1024];
    snprintf(auth_hdr, sizeof(auth_hdr),
        "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", "
        "response=\"%s\", algorithm=MD5\r\n",
        user, realm, nonce, uri, response);

    free(realm);
    free(nonce);

    /* Build SDP from codec tags (or fallback) */
    char *sdp_body = NULL;
    int sdp_len = 0;
    if (call->rtp && call->backbone_tags) {
        struct codec_tag tags[MAX_CODEC_TAGS];
        int tag_count = codec_tags_from_string(call->backbone_tags, tags, MAX_CODEC_TAGS);
        if (tag_count > 0) {
            sdp_body = sdp_build_from_codecs(call->rtp->port, ts->listen_addr,
                                              sdp_addr_family(ts->listen_addr),
                                              tags, tag_count);
            if (sdp_body) sdp_len = (int)strlen(sdp_body);
        }
    }
    if (!sdp_body && call->rtp) {
        const char *af = sdp_addr_family(ts->listen_addr);
        sdp_body = malloc(512);
        sdp_len = snprintf(sdp_body, 512,
            "v=0\r\n"
            "o=- 0 0 %s %s\r\n"
            "s=session\r\n"
            "c=%s %s\r\n"
            "t=0 0\r\n"
            "m=audio %d RTP/AVP 0 8 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n",
            af, ts->listen_addr, af, ts->listen_addr,
            call->rtp->port);
    }

    /* Bump CSeq for the retry */
    call->cseq_num++;

    char invite[4096];
    int ilen = snprintf(invite, sizeof(invite),
        "INVITE %s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
        "From: <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d INVITE\r\n"
        "Contact: <sip:%s@%s>\r\n"
        "User-Agent: upbx-trunk/" TRK_VERSION "\r\n"
        "%s"
        "%s"
        "Content-Length: %d\r\n"
        "\r\n",
        uri,
        ts->listen_addr, call->branch,
        call->trunk_cid ? call->trunk_cid : user, host, call->from_tag,
        call->trunk_did ? call->trunk_did : "?", host,
        call->sip_call_id,
        call->cseq_num,
        user,
        ts->listen_addr,
        auth_hdr,
        sdp_body ? "Content-Type: application/sdp\r\n" : "",
        sdp_len);

    if (ilen > 0 && sdp_len > 0 && ilen + sdp_len < (int)sizeof(invite)) {
        memcpy(invite + ilen, sdp_body, sdp_len);
        ilen += sdp_len;
    }

    send_sip(call->trunk_fd, &ts->target_addr, invite, ilen);
    free(sdp_body);
    log_info("trunk: resent INVITE with auth for %s", call->trunk_did ? call->trunk_did : "?");
}

static void send_invite_to_trunk(struct trunk_state *ts, struct trunk_call *call) {
    struct trk_backbone *target = ts->config->target;
    if (!target || !target->host || !target->port) {
        log_warn("trunk: no target configured for outgoing call");
        return;
    }

    /* Build SDP from codec tags in backbone invite (or fallback to hardcoded) */
    char *sdp_body = NULL;
    int sdp_len = 0;
    if (call->rtp && call->backbone_tags) {
        struct codec_tag tags[MAX_CODEC_TAGS];
        int tag_count = codec_tags_from_string(call->backbone_tags, tags, MAX_CODEC_TAGS);
        if (tag_count > 0) {
            sdp_body = sdp_build_from_codecs(call->rtp->port, ts->listen_addr,
                                              sdp_addr_family(ts->listen_addr),
                                              tags, tag_count);
            if (sdp_body) sdp_len = (int)strlen(sdp_body);
        }
    }
    /* Fallback if no codec tags from backbone */
    if (!sdp_body && call->rtp) {
        const char *af = sdp_addr_family(ts->listen_addr);
        sdp_body = malloc(512);
        sdp_len = snprintf(sdp_body, 512,
            "v=0\r\n"
            "o=- 0 0 %s %s\r\n"
            "s=session\r\n"
            "c=%s %s\r\n"
            "t=0 0\r\n"
            "m=audio %d RTP/AVP 0 8 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n",
            af, ts->listen_addr, af, ts->listen_addr,
            call->rtp->port);
    }

    char invite[4096];
    int ilen = snprintf(invite, sizeof(invite),
        "INVITE sip:%s@%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
        "From: <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:%s@%s>\r\n"
        "User-Agent: upbx-trunk/" TRK_VERSION "\r\n"
        "%s"
        "Content-Length: %d\r\n"
        "\r\n",
        call->trunk_did ? call->trunk_did : "?",
        target->host,
        ts->listen_addr, call->branch,
        call->trunk_cid ? call->trunk_cid : (target->username ? target->username : "trunk"),
        target->host, call->from_tag,
        call->trunk_did ? call->trunk_did : "?",
        target->host,
        call->sip_call_id,
        target->username ? target->username : "",
        ts->listen_addr,
        sdp_body ? "Content-Type: application/sdp\r\n" : "",
        sdp_len);

    if (ilen > 0 && sdp_len > 0 && ilen + sdp_len < (int)sizeof(invite)) {
        memcpy(invite + ilen, sdp_body, sdp_len);
        ilen += sdp_len;
    }

    call->trunk_fd = ts->sip_fds[1];
    call->cseq_num = 1;
    send_sip(call->trunk_fd, &ts->target_addr, invite, ilen);
    free(sdp_body);
    log_info("trunk: sent INVITE to %s:%s for %s", target->host, target->port,
             call->trunk_did ? call->trunk_did : "?");
}

/* ── Backbone→Trunk: incoming backbone invite ────────────────── */

void trunk_handle_backbone_invite(struct trunk_state *ts, const char *call_id,
                                  const char *did, const char *cid,
                                  const char *tags_str) {
    /* Build full tag string for filtering (append trunk-related tags if needed) */
    char full_tags[2048];
    int pos = snprintf(full_tags, sizeof(full_tags), "%s", tags_str ? tags_str : "");

    /* Check filter match */
    if (ts->config->filters && !trunk_any_filter_matches(ts, full_tags)) {
        log_info("trunk: invite %s filtered out (tags: %s)", call_id, full_tags);
        return;
    }

    /* Check for duplicate call_id */
    if (trunk_find_by_backbone_id(ts, call_id)) return;

    /* Create call - re-use backbone call_id as sip_call_id */
    struct trunk_call *call = calloc(1, sizeof(struct trunk_call));
    call->sip_call_id = strdup(call_id);
    strncpy(call->backbone_call_id, call_id, sizeof(call->backbone_call_id) - 1);
    call->direction = CALL_OUTGOING;
    call->state = CALL_WAITING;
    call->trunk_did = strdup(did);
    call->trunk_cid = strdup(cid);
    if (tags_str) call->backbone_tags = strdup(tags_str);

    /* Generate short branch and tag for SIP dialog */
    generate_hex_id(call->branch, sizeof(call->branch));
    generate_hex_id(call->from_tag, sizeof(call->from_tag));

    /* Start delay timer */
    call->delay_active = 1;
    call->delay_started = (int64_t)time(NULL) * 1000;

    call->next = ts->calls;
    ts->calls = call;

    log_info("trunk: backbone invite %s -> %s (delay %dms)", call_id, did, ts->config->delay_ms);
}

/* ── SIP INVITE handler (incoming from trunk) ────────────────── */

static void handle_sip_invite(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                              struct sip_msg *msg) {
    char *dialed = sip_extract_uri_user(msg->uri);
    if (!dialed) dialed = strdup("unknown");

    /* Send 100 Trying */
    char *trying = sip_build_response(100, "Trying", msg, NULL, NULL, 0);
    send_sip(fd, src, trying, (int)strlen(trying));
    free(trying);

    /* Allocate RTP pair */
    struct rtp_pair *rtp = rtp_alloc(&ts->rtp_ctx, ts->target_af);
    if (!rtp) {
        char *resp = sip_build_response(500, "Server Internal Error", msg, NULL, NULL, 0);
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        free(dialed);
        return;
    }
    rtp->is_backbone_dir = 1;
    rtp->backbone = ts->backbone;

    /* Parse remote SDP to learn trunk provider's media address */
    if (msg->body && msg->body_len > 0) {
        struct sdp_info *sdp = sdp_parse(msg->body, msg->body_len);
        if (sdp && sdp->c_addr && sdp->m_port > 0) {
            rtp_set_remote(rtp, sdp->c_addr, sdp->m_port);
            log_info("trunk: learned remote media %s:%d from SDP", sdp->c_addr, sdp->m_port);
        }
        if (sdp) sdp_free(sdp);
    }

    /* Generate backbone call_id */
    struct trunk_call *call = calloc(1, sizeof(struct trunk_call));
    call->sip_call_id = strdup(msg->call_id);
    generate_hex_id(call->backbone_call_id, 33);
    strncpy(rtp->call_id, call->backbone_call_id, sizeof(rtp->call_id) - 1);

    call->trunk_addr = *src;
    call->trunk_fd = fd;
    call->trunk_did = dialed;
    call->trunk_cid = strdup(msg->from ? msg->from : "unknown");
    call->cseq_num = msg->cseq_num;
    call->rtp = rtp;
    call->direction = CALL_INCOMING;
    call->state = CALL_RINGING;

    /* Store dialog headers */
    if (msg->via)     call->trunk_via     = strdup(msg->via);
    if (msg->from)    call->trunk_from    = strdup(msg->from);
    if (msg->contact) call->trunk_contact = strdup(msg->contact);

    /* Build to-tag */
    generate_hex_id(call->gw_tag, sizeof(call->gw_tag));
    {
        const char *orig_to = msg->to ? msg->to : "";
        size_t tlen = strlen(orig_to) + 6 + strlen(call->gw_tag) + 1;
        call->trunk_to = malloc(tlen);
        snprintf(call->trunk_to, tlen, "%s;tag=%s", orig_to, call->gw_tag);
    }

    call->next = ts->calls;
    ts->calls = call;

    /* Send invite to backbone with trunk=<username> tag */
    {
        char tags[256];
        snprintf(tags, sizeof(tags), "trunk=%s",
                 ts->config->backbones && ts->config->backbones->username
                 ? ts->config->backbones->username : "trunk");
        backbone_send_invite(ts->backbone, call->backbone_call_id, dialed,
                            call->trunk_cid, tags);
    }

    log_info("trunk: incoming call from trunk for %s, backbone id %s", dialed, call->backbone_call_id);
}

/* ── SIP BYE handler ─────────────────────────────────────────── */

static void handle_sip_bye(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                           struct sip_msg *msg) {
    log_info("trunk: received BYE from upstream, call_id=%s", msg->call_id ? msg->call_id : "?");

    struct trunk_call *call = trunk_find_by_sip_id(ts, msg->call_id);
    if (!call) {
        log_warn("trunk: BYE for unknown call %s", msg->call_id ? msg->call_id : "?");
        char *ok = sip_build_response(200, "OK", msg, NULL, NULL, 0);
        send_sip(fd, src, ok, (int)strlen(ok));
        free(ok);
        return;
    }

    char *ok = sip_build_response(200, "OK", msg, NULL, NULL, 0);
    send_sip(fd, src, ok, (int)strlen(ok));
    free(ok);

    log_info("trunk: forwarding BYE to backbone for %s", call->backbone_call_id);
    backbone_send_bye(ts->backbone, call->backbone_call_id);

    trunk_call_remove(ts, call);
}

/* ── SIP CANCEL handler ──────────────────────────────────────── */

static void handle_sip_cancel(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                              struct sip_msg *msg) {
    char *ok = sip_build_response(200, "OK", msg, NULL, NULL, 0);
    send_sip(fd, src, ok, (int)strlen(ok));
    free(ok);

    struct trunk_call *call = trunk_find_by_sip_id(ts, msg->call_id);
    if (!call) return;

    if (call->direction == CALL_INCOMING) {
        backbone_send_cancel(ts->backbone, call->backbone_call_id);
    }

    trunk_call_remove(ts, call);
}

/* ── SIP response handler (from trunk provider) ──────────────── */

static void handle_sip_response(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                                struct sip_msg *msg) {
    struct trunk_call *call = trunk_find_by_sip_id(ts, msg->call_id);
    if (!call) return;

    int code = msg->status_code;

    if (code == 100) return; /* absorb 100 Trying */

    /* Parse SDP from any provisional or success response */
    char *codec_tags = NULL;
    if ((code == 180 || code == 183 || code == 200) && msg->body && msg->body_len > 0 && call->rtp) {
        struct sdp_info *sdp = sdp_parse(msg->body, msg->body_len);
        if (sdp && sdp->c_addr && sdp->m_port > 0) {
            free(call->remote_sdp_host);
            call->remote_sdp_host = strdup(sdp->c_addr);
            call->remote_sdp_port = sdp->m_port;
            rtp_set_remote(call->rtp, sdp->c_addr, sdp->m_port);
            log_info("trunk: %d SDP remote %s:%d for %s", code, sdp->c_addr, sdp->m_port, call->backbone_call_id);
        }
        if (sdp && sdp->codec_count > 0) {
            codec_tags = codec_tags_to_string(sdp->codecs, sdp->codec_count);
            log_info("trunk: %d parsed %d codec tags: %s", code, sdp->codec_count, codec_tags ? codec_tags : "(null)");
        } else if (sdp) {
            log_info("trunk: %d SDP parsed but no codecs (body_len=%d, m_port=%d)", code, msg->body_len, sdp->m_port);
        }
        if (sdp) sdp_free(sdp);
    }

    if (code == 180) {
        if (call->state < CALL_RINGING) {
            call->state = CALL_RINGING;
            backbone_send_ringing(ts->backbone, call->backbone_call_id, codec_tags ? codec_tags : "");
        }
        free(codec_tags);
    } else if (code == 200) {
        if (call->state == CALL_ACTIVE) { free(codec_tags); return; }

        /* Send synthetic ringing if upstream skipped 180 */
        if (call->state < CALL_RINGING) {
            backbone_send_ringing(ts->backbone, call->backbone_call_id, codec_tags ? codec_tags : "");
            log_info("trunk: sent synthetic ringing for %s (upstream skipped 180)", call->backbone_call_id);
        }

        call->state = CALL_ACTIVE;

        /* Store To header (with remote tag) for BYE dialog matching */
        if (msg->to) {
            free(call->trunk_to);
            call->trunk_to = strdup(msg->to);
        }

        /* Send ACK (no SDP — upstream learns our address from RTP) */
        {
            struct trk_backbone *target = ts->config->target;
            const char *host = target ? target->host : "0.0.0.0";
            char ack[2048];
            int alen = snprintf(ack, sizeof(ack),
                "ACK sip:%s@%s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
                "From: <sip:%s@%s>;tag=%s\r\n"
                "To: %s\r\n"
                "Call-ID: %s\r\n"
                "CSeq: %d ACK\r\n"
                "Contact: <sip:%s@%s>\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                call->trunk_did ? call->trunk_did : "?", host,
                ts->listen_addr, call->branch,
                call->trunk_cid ? call->trunk_cid : (target && target->username ? target->username : "trunk"), host, call->from_tag,
                msg->to ? msg->to : "",
                call->sip_call_id,
                call->cseq_num,
                target && target->username ? target->username : "",
                ts->listen_addr);
            call->trunk_addr = *src;
            call->trunk_fd = fd;
            send_sip(fd, src, ack, alen);
            log_info("trunk: sent ACK to upstream for %s", call->backbone_call_id);
        }

        backbone_send_answer(ts->backbone, call->backbone_call_id, codec_tags ? codec_tags : "");
        log_info("trunk: call %s established", call->backbone_call_id);
        free(codec_tags);

    } else if (code == 401 && msg->www_authenticate && call->cseq_num < 2) {
        log_info("trunk: call %s got 401 challenge, resending with auth", call->backbone_call_id);
        resend_invite_with_auth(ts, call, msg->www_authenticate);
    } else if (code >= 400) {
        log_info("trunk: call %s rejected with %d", call->backbone_call_id, code);
        backbone_send_cancel(ts->backbone, call->backbone_call_id);
        trunk_call_remove(ts, call);
    }
}

/* ── SIP receive task ────────────────────────────────────────── */

int trunk_sip_recv_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct trunk_state *state = pt->udata;

    /* Registration lifecycle — single action per call */
    int64_t now_ms = (int64_t)time(NULL) * 1000;
    if (!state->reg_registered && state->reg_last_send == 0) {
        /* First boot: send initial REGISTER */
        trunk_send_register(state);
    } else if (state->reg_registered) {
        /* Re-register 15s before expiry */
        int re_reg_ms = (state->reg_expires - 15) * 1000;
        if (re_reg_ms < 5000) re_reg_ms = state->reg_expires * 500;
        if (now_ms - state->reg_last_send >= (int64_t)re_reg_ms) {
            state->reg_registered = 0;
            trunk_send_register(state);
        }
    } else if (!state->reg_registered && now_ms - state->reg_last_send > 30000) {
        /* No response in 30s, retry */
        trunk_send_register(state);
    }

    int ready_fd = sched_has_data(state->sip_fds);
    if (ready_fd < 0) return SCHED_RUNNING;

    char buf[4096];
    struct sockaddr_storage src;
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(ready_fd, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr *)&src, &src_len);
    if (n <= 0) return SCHED_RUNNING;

    buf[n] = '\0';
    log_debug("sip: <<< %.*s", (int)n, buf);

    struct sip_msg *msg = sip_parse_request(buf, (int)n);
    if (!msg) return SCHED_RUNNING;

    if (msg->status_code == 0 && msg->method_str) {
        log_info("trunk: received SIP %s from upstream", msg->method_str);
    } else if (msg->status_code > 0) {
        log_info("trunk: received SIP %d %s from upstream (CSeq: %s)",
                 msg->status_code, msg->reason ? msg->reason : "?",
                 msg->cseq_method ? msg->cseq_method : "?");
    }

    if (msg->status_code > 0) {
        if (msg->cseq_method && strcasecmp(msg->cseq_method, "REGISTER") == 0) {
            /* REGISTER response — handle inline */
            if (msg->status_code == 401 && msg->www_authenticate) {
                log_info("trunk: REGISTER got 401, authenticating");
                trunk_send_register_auth(state, msg->www_authenticate);
            } else if (msg->status_code == 200) {
                state->reg_expires = msg->expires > 0 ? msg->expires : 300;
                state->reg_registered = 1;
                log_info("trunk: REGISTER OK, expires=%d", state->reg_expires);
            }
        } else {
            handle_sip_response(ready_fd, state, &src, msg);
        }
    } else {
        switch (msg->method) {
        case SIP_METHOD_INVITE:
            handle_sip_invite(ready_fd, state, &src, msg);
            break;
        case SIP_METHOD_BYE:
            handle_sip_bye(ready_fd, state, &src, msg);
            break;
        case SIP_METHOD_CANCEL:
            handle_sip_cancel(ready_fd, state, &src, msg);
            break;
        case SIP_METHOD_OPTIONS: {
            char *resp = sip_build_response(200, "OK", msg, NULL, NULL, 0);
            send_sip(ready_fd, &src, resp, (int)strlen(resp));
            free(resp);
            break;
        }
        case SIP_METHOD_ACK:
            break;
        default:
            break;
        }
    }

    sip_msg_free(msg);
    return SCHED_RUNNING;
}

/* ── Delay task (checks for expired delay timers) ────────────── */

int trunk_delay_task(int64_t ts, struct pt_task *pt) {
    struct trunk_state *state = pt->udata;
    int64_t now_ms = (int64_t)time(NULL) * 1000;

    for (struct trunk_call *call = state->calls; call; call = call->next) {
        if (!call->delay_active) continue;
        if (call->direction != CALL_OUTGOING) continue;

        int64_t elapsed = now_ms - call->delay_started;
        if (elapsed >= state->config->delay_ms) {
            call->delay_active = 0;

            /* Check if call was cancelled during delay */
            if (call->state == CALL_ENDED) continue;

            /* Allocate RTP pair for the outgoing call */
            call->rtp = rtp_alloc(&state->rtp_ctx, state->target_af);
            if (!call->rtp) {
                log_warn("trunk: failed to allocate RTP for outgoing call %s", call->backbone_call_id);
                trunk_call_remove(state, call);
                continue;
            }
            call->rtp->is_backbone_dir = 1;
            call->rtp->backbone = state->backbone;
            strncpy(call->rtp->call_id, call->backbone_call_id, sizeof(call->rtp->call_id) - 1);

            /* Send SIP INVITE to trunk provider */
            send_invite_to_trunk(state, call);
        }
    }

    return SCHED_RUNNING;
}

/* ── Backbone event callbacks ────────────────────────────────── */

void trunk_on_backbone_ringing(struct trunk_state *s, const char *call_id, const char *codec_tags) {
    /* For incoming calls: ignore (trunk doesn't send ringing back to SIP trunk) */
    (void)s; (void)call_id;
}

void trunk_on_backbone_answer(struct trunk_state *s, const char *call_id, const char *codec_tags) {
    struct trunk_call *call = trunk_find_by_backbone_id(s, call_id);
    if (!call || call->direction != CALL_INCOMING) return;

    call->state = CALL_ACTIVE;

    /* Send 200 OK to trunk with SDP pointing to our RTP port */
    char sdp_body[512];
    int sdp_len = 0;
    if (call->rtp) {
        const char *af = sdp_addr_family(s->listen_addr);
        sdp_len = snprintf(sdp_body, sizeof(sdp_body),
            "v=0\r\n"
            "o=- 0 0 %s %s\r\n"
            "s=session\r\n"
            "c=%s %s\r\n"
            "t=0 0\r\n"
            "m=audio %d RTP/AVP 0 8 101\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n",
            af, s->listen_addr, af, s->listen_addr,
            call->rtp->port);
    }

    char resp[4096];
    int rlen = snprintf(resp, sizeof(resp),
        "SIP/2.0 200 OK\r\n"
        "Via: %s\r\n"
        "From: %s\r\n"
        "To: %s\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d INVITE\r\n"
        "Contact: <sip:%s@%s>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        call->trunk_via ? call->trunk_via : "",
        call->trunk_from ? call->trunk_from : "",
        call->trunk_to ? call->trunk_to : "",
        call->sip_call_id,
        call->cseq_num,
        s->config->target && s->config->target->username ? s->config->target->username : "",
        s->listen_addr,
        sdp_len);

    if (rlen > 0 && sdp_len > 0 && rlen + sdp_len < (int)sizeof(resp)) {
        memcpy(resp + rlen, sdp_body, sdp_len);
        rlen += sdp_len;
    }

    send_sip(call->trunk_fd, &call->trunk_addr, resp, rlen);
    log_info("trunk: answered call %s to trunk", call_id);
}

void trunk_on_backbone_cancel(struct trunk_state *s, const char *call_id) {
    struct trunk_call *call = trunk_find_by_backbone_id(s, call_id);
    if (!call) return;

    if (call->direction == CALL_OUTGOING && call->delay_active) {
        /* Still waiting for delay, just cancel */
        call->delay_active = 0;
        call->state = CALL_ENDED;
        trunk_call_remove(s, call);
        return;
    }

    if (call->direction == CALL_OUTGOING) {
        /* Send CANCEL to trunk */
        if (call->trunk_fd >= 0) {
            struct trk_backbone *target = s->config->target;
            const char *host = target ? target->host : "0.0.0.0";
            char cancel[512];
            int clen = snprintf(cancel, sizeof(cancel),
                "CANCEL sip:%s@%s SIP/2.0\r\n"
                "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
                "From: <sip:%s@%s>;tag=%s\r\n"
                "To: <sip:%s@%s>\r\n"
                "Call-ID: %s\r\n"
                "CSeq: 1 CANCEL\r\n"
                "Content-Length: 0\r\n"
                "\r\n",
                call->trunk_did ? call->trunk_did : "?",
                host,
                s->listen_addr, call->branch,
                call->trunk_cid ? call->trunk_cid : (target && target->username ? target->username : "trunk"),
                host, call->from_tag,
                call->trunk_did ? call->trunk_did : "?",
                host,
                call->sip_call_id);
            send_sip(call->trunk_fd, &s->target_addr, cancel, clen);
            log_info("trunk: sent CANCEL to upstream for %s", call->backbone_call_id);
        }
    }

    trunk_call_remove(s, call);
}

void trunk_on_backbone_media(struct trunk_state *s, const char *call_id, int stream_id,
                             const uint8_t *data, size_t len) {
    struct trunk_call *call = trunk_find_by_backbone_id(s, call_id);
    if (!call) return;
    if (call->state != CALL_ACTIVE) return;
    if (!call->rtp) {
        log_warn("trunk: media for %s but no RTP pair", call_id);
        return;
    }
    if (!call->rtp->learned_ext) {
        log_warn("trunk: media for %s but no remote RTP address", call_id);
        return;
    }

    /* Log first outbound RTP packet for diagnostics */
    if (!call->media_logged) {
        char ip[INET6_ADDRSTRLEN];
        sockaddr_to_str(&call->rtp->ext_addr, ip, sizeof(ip));
        log_info("trunk: first RTP out for %s -> %s:%d (local port %d, fd %d, %zu bytes)",
                 call->backbone_call_id, ip, sockaddr_port(&call->rtp->ext_addr),
                 call->rtp->port, call->rtp->fd, len);

        /* Test sendto with correct addrlen and log any error */
        ssize_t sent = sendto(call->rtp->fd, data, len, 0,
                              (struct sockaddr *)&call->rtp->ext_addr,
                              get_addrlen(&call->rtp->ext_addr));
        if (sent < 0) {
            log_error("trunk: first RTP sendto failed: %s (errno=%d)", strerror(errno), errno);
        } else {
            log_info("trunk: first RTP sendto ok, %zd bytes sent", sent);
        }
        call->media_logged = 1;
        return;
    }

    /* Send RTP to trunk provider (remote address learned from SDP) */
    rtp_send_to_ext(call->rtp, data, len);
}

void trunk_on_backbone_bye(struct trunk_state *s, const char *call_id) {
    struct trunk_call *call = trunk_find_by_backbone_id(s, call_id);
    if (!call) return;

    /* Send BYE to trunk */
    if (call->trunk_fd >= 0) {
        struct trk_backbone *target = s->config->target;
        const char *host = target ? target->host : "0.0.0.0";
        char bye[1024];
        int blen = snprintf(bye, sizeof(bye),
            "BYE sip:%s@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s;branch=z9hG4bKbye%s\r\n"
            "From: <sip:%s@%s>;tag=%s\r\n"
            "To: %s\r\n"
            "Call-ID: %s\r\n"
            "CSeq: %d BYE\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            call->trunk_did ? call->trunk_did : "?", host,
            s->listen_addr, call->branch,
            call->trunk_cid ? call->trunk_cid : (target && target->username ? target->username : "trunk"), host, call->from_tag,
            call->trunk_to ? call->trunk_to : "",
            call->sip_call_id,
            call->cseq_num + 1);
        send_sip(call->trunk_fd, &call->trunk_addr, bye, blen);
        log_info("trunk: sent BYE to upstream for %s", call->backbone_call_id);
    }

    trunk_call_remove(s, call);
}

/* ── Public API ──────────────────────────────────────────────── */

struct trunk_state *trunk_create(struct trk_config *cfg) {
    struct trunk_state *ts = calloc(1, sizeof(struct trunk_state));
    if (!ts) return NULL;
    ts->config = cfg;
    ts->sip_fds = NULL;
    strncpy(ts->listen_addr, "0.0.0.0", sizeof(ts->listen_addr) - 1);
    rtp_ctx_init(&ts->rtp_ctx, cfg->rtp_min, cfg->rtp_max);
    return ts;
}

void trunk_free(struct trunk_state *ts) {
    if (!ts) return;
    if (ts->sip_task) sched_remove(ts->sip_task);
    if (ts->delay_task) sched_remove(ts->delay_task);
    while (ts->calls) {
        struct trunk_call *next = ts->calls->next;
        trunk_call_free(ts->calls);
        ts->calls = next;
    }
    free(ts);
}
