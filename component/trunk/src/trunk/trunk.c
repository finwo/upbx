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
    ssize_t sent = sendto(fd, data, (size_t)len, 0,
                          (struct sockaddr *)dst, get_addrlen(dst));
    if (sent < 0) {
        log_error("trunk: sendto failed: %s (errno=%d)", strerror(errno), errno);
    } else {
        log_info("trunk: >>> SIP to %s:%d fd=%d (%zd/%d bytes)\n%.*s",
                 ip, sockaddr_port(dst), fd, sent, len, len, data);
    }
}

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
            if (!tag->value) return 1;
            if (!eq) return 0;

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

static void build_sdp_body(char *sdp_buf, size_t sdp_buf_size, struct rtp_pair *rtp,
                           const char *listen_ip, struct codec_tag *tags, int tag_count) {
    const char *af = sdp_addr_family(listen_ip);

    int pos = snprintf(sdp_buf, sdp_buf_size,
        "v=0\r\n"
        "o=- 0 0 IN %s %s\r\n"
        "s=session\r\n"
        "c=IN %s %s\r\n"
        "t=0 0\r\n",
        af, listen_ip, af, listen_ip);

    if (tag_count > 0 && rtp->port > 0) {
        char pt_list[256] = {0};
        int pt_len = 0;
        for (int i = 0; i < tag_count; i++) {
            if (i > 0) pt_list[pt_len++] = ' ';
            pt_len += snprintf(pt_list + pt_len, sizeof(pt_list) - (size_t)pt_len, "%d", tags[i].stream_id);
        }

        pos += snprintf(sdp_buf + pos, sdp_buf_size - (size_t)pos,
            "m=%s %d RTP/AVP %s\r\n", tags[0].media_type, rtp->port, pt_list);

        for (int i = 0; i < tag_count; i++) {
            pos += snprintf(sdp_buf + pos, sdp_buf_size - (size_t)pos,
                "a=rtpmap:%d %s\r\n", tags[i].stream_id, tags[i].codec);
        }
    }
}

static void resend_invite_with_auth(struct trunk_state *ts, struct trunk_call *call,
                                    const char *www_auth) {
    struct trk_backbone *target = ts->config->target;
    if (!target || !target->host || !target->username || !target->password) return;

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

    char ha1_input[512];
    snprintf(ha1_input, sizeof(ha1_input), "%s:%s:%s", user, realm, pass);
    char ha1[33];
    md5_hexdigest(ha1_input, ha1);

    char uri[256];
    snprintf(uri, sizeof(uri), "sip:%s@%s",
             call->trunk_did ? call->trunk_did : "?", host);
    char ha2_input[512];
    snprintf(ha2_input, sizeof(ha2_input), "INVITE:%s", uri);
    char ha2[33];
    md5_hexdigest(ha2_input, ha2);

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

    char sdp_body[2048] = {0};
    struct codec_tag tags[MAX_CODEC_TAGS];
    int tag_count = codec_tags_from_string(call->backbone_tags, tags, MAX_CODEC_TAGS);
    if (tag_count > 0) {
        build_sdp_body(sdp_body, sizeof(sdp_body), call->rtp, ts->listen_addr, tags, tag_count);
    }

    call->cseq_num++;

    char invite[4096];
    int ilen = snprintf(invite, sizeof(invite),
        "INVITE %s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:%s@%s>;tag=%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: %s\r\n"
        "CSeq: %d INVITE\r\n"
        "Contact: <sip:%s@%s>\r\n"
        "User-Agent: upbx-trunk/" TRK_VERSION "\r\n"
        "%s"
        "Content-Length: %d\r\n"
        "\r\n",
        uri,
        ts->listen_addr, call->branch,
        call->trunk_cid ? call->trunk_cid : user, ts->listen_addr, call->from_tag,
        call->trunk_did ? call->trunk_did : "?", host,
        call->sip_call_id,
        call->cseq_num,
        user,
        ts->listen_addr,
        auth_hdr,
        (int)strlen(sdp_body));

    if (ilen > 0 && sdp_body[0]) {
        memcpy(invite + ilen, sdp_body, strlen(sdp_body));
        ilen += (int)strlen(sdp_body);
    }

    send_sip(call->trunk_fd, &ts->target_addr, invite, ilen);
    log_info("trunk: resent INVITE with auth for %s", call->trunk_did ? call->trunk_did : "?");
}

static void send_invite_to_trunk(struct trunk_state *ts, struct trunk_call *call) {
    struct trk_backbone *target = ts->config->target;
    if (!target || !target->host || !target->port) {
        log_warn("trunk: no target configured for outgoing call");
        return;
    }

    char sdp_body[2048] = {0};
    struct codec_tag tags[MAX_CODEC_TAGS];
    int tag_count = codec_tags_from_string(call->backbone_tags, tags, MAX_CODEC_TAGS);
    if (tag_count > 0) {
        build_sdp_body(sdp_body, sizeof(sdp_body), call->rtp, ts->listen_addr, tags, tag_count);
    }

    char invite[4096];
    int ilen = snprintf(invite, sizeof(invite),
        "INVITE sip:%s@%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
        "Max-Forwards: 70\r\n"
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
        ts->listen_addr, call->from_tag,
        call->trunk_did ? call->trunk_did : "?",
        target->host,
        call->sip_call_id,
        target->username ? target->username : "",
        ts->listen_addr,
        sdp_body[0] ? "Content-Type: application/sdp\r\n" : "",
        (int)strlen(sdp_body));

    if (ilen > 0 && sdp_body[0]) {
        memcpy(invite + ilen, sdp_body, strlen(sdp_body));
        ilen += (int)strlen(sdp_body);
    }

    call->trunk_fd = ts->sip_fds[1];
    call->cseq_num = 1;
    send_sip(call->trunk_fd, &ts->target_addr, invite, ilen);
    log_info("trunk: sent INVITE to %s:%s for %s", target->host, target->port,
             call->trunk_did ? call->trunk_did : "?");
}

void trunk_on_backbone_invite(struct trunk_state *ts, const char *call_id,
                              const char *did, const char *cid,
                              const char *tags_str) {
    char full_tags[2048];
    snprintf(full_tags, sizeof(full_tags), "%s", tags_str ? tags_str : "");

    if (ts->config->filters && !trunk_any_filter_matches(ts, full_tags)) {
        log_info("trunk: invite %s filtered out (tags: %s)", call_id, full_tags);
        return;
    }

    if (call_lookup(ts->calls, call_id)) return;

    struct trunk_call *call = call_create(ts->calls, call_id, call_id);
    if (!call) return;

    call->trunk_did = strdup(did);
    call->trunk_cid = strdup(cid);
    if (tags_str) call->backbone_tags = strdup(tags_str);

    generate_hex_id(call->branch, sizeof(call->branch));
    generate_hex_id(call->from_tag, sizeof(call->from_tag));

    call->delay_active = 1;
    call->delay_started = (int64_t)time(NULL) * 1000;

    log_info("trunk: backbone invite %s -> %s (delay %dms)", call_id, did, ts->config->delay_ms);
}

static void on_provider_invite(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                              struct sip_msg *msg) {
    char *dialed = sip_extract_uri_user(msg->uri);
    if (!dialed) dialed = strdup("unknown");

    char *trying = sip_build_response(100, "Trying", msg, NULL, NULL, 0);
    send_sip(fd, src, trying, (int)strlen(trying));
    free(trying);

    struct rtp_pair *rtp = rtp_alloc(&ts->rtp_ctx, ts->target_af);
    if (!rtp) {
        char *resp = sip_build_response(500, "Server Internal Error", msg, NULL, NULL, 0);
        send_sip(fd, src, resp, (int)strlen(resp));
        free(resp);
        free(dialed);
        return;
    }
    rtp->backbone = ts->backbone;

    char *codec_tags = NULL;
    if (msg->body && msg->body_len > 0) {
        struct sdp_info *sdp = sdp_parse(msg->body, msg->body_len);
        if (sdp && sdp->c_addr && sdp->m_port > 0) {
            rtp_set_remote(rtp, sdp->c_addr, sdp->m_port);
            log_info("trunk: learned remote media %s:%d from SDP", sdp->c_addr, sdp->m_port);
        }
        if (sdp && sdp->codec_count > 0) {
            codec_tags = codec_tags_to_string(sdp->codecs, sdp->codec_count);
            log_info("trunk: parsed %d codecs from SDP: %s", sdp->codec_count, codec_tags);
        }
        if (sdp) sdp_free(sdp);
    }

    char call_id[33];
    generate_hex_id(call_id, sizeof(call_id));
    strncpy(rtp->call_id, call_id, sizeof(rtp->call_id) - 1);

    struct trunk_call *call = call_create(ts->calls, call_id, msg->call_id);
    if (!call) {
        rtp_free(rtp);
        free(dialed);
        free(codec_tags);
        return;
    }

    call->trunk_addr = *src;
    call->trunk_fd = fd;
    call->trunk_did = dialed;
    {
        char *cid = NULL;
        if (msg->from) {
            const char *start = strchr(msg->from, '<');
            const char *end = start ? strchr(start, '>') : NULL;
            if (start && end && end > start) {
                size_t urilen = (size_t)(end - start - 1);
                char *uri = malloc(urilen + 1);
                memcpy(uri, start + 1, urilen);
                uri[urilen] = '\0';
                cid = sip_extract_uri_user(uri);
                free(uri);
            }
            if (!cid) cid = strdup(msg->from);
        }
        call->trunk_cid = cid ? cid : strdup("unknown");
    }
    call->cseq_num = msg->cseq_num;
    call->rtp = rtp;
    call->state = CALL_RINGING;

    if (msg->via)     call->trunk_via     = strdup(msg->via);
    if (msg->from)    call->trunk_from    = strdup(msg->from);
    if (msg->contact) call->trunk_contact = strdup(msg->contact);

    generate_hex_id(call->branch, sizeof(call->branch));

    generate_hex_id(call->gw_tag, sizeof(call->gw_tag));
    {
        const char *orig_to = msg->to ? msg->to : "";
        size_t tlen = strlen(orig_to) + 6 + strlen(call->gw_tag) + 1;
        call->trunk_to = malloc(tlen);
        snprintf(call->trunk_to, tlen, "%s;tag=%s", orig_to, call->gw_tag);
    }

    char tags[4096];
    int tlen = snprintf(tags, sizeof(tags), "trunk=%s",
                        ts->config->backbones && ts->config->backbones->username
                        ? ts->config->backbones->username : "trunk");
    if (codec_tags && codec_tags[0]) {
        tlen += snprintf(tags + tlen, sizeof(tags) - (size_t)tlen, " %s", codec_tags);
    }
    backbone_send_invite(ts->backbone, call_id, dialed, call->trunk_cid, tags);
    free(codec_tags);

    log_info("trunk: incoming call from provider for %s, call id %s", dialed, call_id);
}

static void on_provider_bye(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                           struct sip_msg *msg) {
    log_info("trunk: received BYE from upstream, call_id=%s", msg->call_id ? msg->call_id : "?");

    struct trunk_call *call = call_lookup(ts->calls, msg->call_id);
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

    log_info("trunk: forwarding BYE to backbone for %s", call->call_id);
    backbone_send_bye(ts->backbone, call->call_id);

    call_destroy(ts->calls, call);
}

static void on_provider_cancel(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                              struct sip_msg *msg) {
    char *ok = sip_build_response(200, "OK", msg, NULL, NULL, 0);
    send_sip(fd, src, ok, (int)strlen(ok));
    free(ok);

    struct trunk_call *call = call_lookup(ts->calls, msg->call_id);
    if (!call) return;

    backbone_send_cancel(ts->backbone, call->call_id);
    call_destroy(ts->calls, call);
}

static void on_provider_response(int fd, struct trunk_state *ts, struct sockaddr_storage *src,
                                struct sip_msg *msg) {
    struct trunk_call *call = call_lookup(ts->calls, msg->call_id);
    if (!call) return;

    int code = msg->status_code;

    if (code == 100) return;

    char *codec_tags = NULL;
    if ((code == 180 || code == 183 || code == 200) && msg->body && msg->body_len > 0 && call->rtp) {
        struct sdp_info *sdp = sdp_parse(msg->body, msg->body_len);
        if (sdp && sdp->c_addr && sdp->m_port > 0) {
            free(call->remote_sdp_host);
            call->remote_sdp_host = strdup(sdp->c_addr);
            call->remote_sdp_port = sdp->m_port;
            rtp_set_remote(call->rtp, sdp->c_addr, sdp->m_port);
            log_info("trunk: %d SDP remote %s:%d for %s", code, sdp->c_addr, sdp->m_port, call->call_id);
        }
        if (sdp && sdp->codec_count > 0) {
            codec_tags = codec_tags_to_string(sdp->codecs, sdp->codec_count);
            log_info("trunk: %d parsed %d codec tags: %s", code, sdp->codec_count, codec_tags ? codec_tags : "(null)");
        }
        if (sdp) sdp_free(sdp);
    }

    if (code == 180) {
        if (call->state < CALL_RINGING) {
            call->state = CALL_RINGING;
            backbone_send_ringing(ts->backbone, call->call_id, codec_tags ? codec_tags : "");
        }
        free(codec_tags);
    } else if (code == 200) {
        if (call->state == CALL_ACTIVE) { free(codec_tags); return; }

        if (call->state < CALL_RINGING) {
            backbone_send_ringing(ts->backbone, call->call_id, codec_tags ? codec_tags : "");
            log_info("trunk: sent synthetic ringing for %s (upstream skipped 180)", call->call_id);
        }

        call->state = CALL_ACTIVE;

        if (msg->to) {
            free(call->trunk_to);
            call->trunk_to = strdup(msg->to);
        }

        struct trk_backbone *target = ts->config->target;
        const char *host = target ? target->host : "0.0.0.0";
        char ack[2048];
        int alen = snprintf(ack, sizeof(ack),
            "ACK sip:%s@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:%s@%s>;tag=%s\r\n"
            "To: %s\r\n"
            "Call-ID: %s\r\n"
            "CSeq: %d ACK\r\n"
            "Contact: <sip:%s@%s>\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            call->trunk_did ? call->trunk_did : "?",
            host,
            ts->listen_addr, call->branch,
            call->trunk_cid ? call->trunk_cid : (target && target->username ? target->username : "trunk"),
            ts->listen_addr, call->from_tag,
            msg->to ? msg->to : "",
            call->sip_call_id,
            call->cseq_num,
            target && target->username ? target->username : "",
            ts->listen_addr);
        call->trunk_addr = *src;
        call->trunk_fd = fd;
        send_sip(fd, src, ack, alen);
        log_info("trunk: sent ACK to upstream for %s", call->call_id);

        backbone_send_answer(ts->backbone, call->call_id, codec_tags ? codec_tags : "");
        log_info("trunk: call %s established", call->call_id);
        free(codec_tags);

    } else if (code == 401 && msg->www_authenticate && call->cseq_num < 2) {
        log_info("trunk: call %s got 401 challenge, resending with auth", call->call_id);
        resend_invite_with_auth(ts, call, msg->www_authenticate);
    } else if (code >= 400) {
        log_info("trunk: call %s rejected with %d", call->call_id, code);
        backbone_send_cancel(ts->backbone, call->call_id);
        call_destroy(ts->calls, call);
    }
}

int trunk_sip_recv_task(int64_t ts, struct pt_task *pt) {
    struct trunk_state *state = pt->udata;

    int64_t now_ms = ts;
    if (now_ms >= state->reg_refresh_at) {
        trunk_send_register(state);
        state->reg_refresh_at = now_ms + 10000;
    }

    if (state->reg_registered && now_ms - state->keepalive_last_send >= 25000) {
        const char *ping = "\r\n";
        sendto(state->sip_fds[1], ping, 2, 0,
               (struct sockaddr *)&state->target_addr, state->target_addrlen);
        state->keepalive_last_send = now_ms;
        log_debug("trunk: sent NAT keepalive ping");
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
    log_info("sip: <<< %.*s", (int)n, buf);

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
            if (msg->status_code == 401 && msg->www_authenticate) {
                log_info("trunk: REGISTER got 401, authenticating");
                trunk_send_register_auth(state, msg->www_authenticate);
            } else if (msg->status_code == 200) {
                int expires = 300;
                if (msg->contact) {
                    const char *exp_str = strstr(msg->contact, "expires=");
                    if (exp_str) expires = atoi(exp_str + 8);
                }
                if (expires <= 0) expires = 300;
                state->reg_expires = expires;
                state->reg_registered = 1;
                state->reg_refresh_at = now_ms + (int64_t)expires * 1000 - 15000;
                log_info("trunk: REGISTER OK, expires=%d, next refresh in %d seconds",
                         state->reg_expires, expires - 15);
            }
        } else {
            on_provider_response(ready_fd, state, &src, msg);
        }
    } else {
        switch (msg->method) {
        case SIP_METHOD_INVITE:
            on_provider_invite(ready_fd, state, &src, msg);
            break;
        case SIP_METHOD_BYE:
            on_provider_bye(ready_fd, state, &src, msg);
            break;
        case SIP_METHOD_CANCEL:
            on_provider_cancel(ready_fd, state, &src, msg);
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

int trunk_delay_task(int64_t ts, struct pt_task *pt) {
    struct trunk_state *state = pt->udata;
    int64_t now_ms = ts;

    for (size_t i = 0; i < mindex_length(state->calls); i++) {
        struct trunk_call *call = (struct trunk_call *)mindex_nth(state->calls, (int)i);
        if (!call || !call->delay_active) continue;

        int64_t elapsed = now_ms - call->delay_started;
        if (elapsed >= state->config->delay_ms) {
            call->delay_active = 0;

            if (call->state == CALL_ENDED) continue;

            call->rtp = rtp_alloc(&state->rtp_ctx, state->target_af);
            if (!call->rtp) {
                log_warn("trunk: failed to allocate RTP for outgoing call %s", call->call_id);
                call_destroy(state->calls, call);
                continue;
            }
            call->rtp->backbone = state->backbone;
            strncpy(call->rtp->call_id, call->call_id, sizeof(call->rtp->call_id) - 1);

            send_invite_to_trunk(state, call);
        }
    }

    return SCHED_RUNNING;
}

void trunk_on_backbone_ringing(struct trunk_state *s, const char *call_id,
                              const char *codec_tags) {
    struct trunk_call *call = call_lookup(s->calls, call_id);
    if (!call) return;

    char sdp_body[2048] = {0};
    int sdp_len = 0;
    if (codec_tags && codec_tags[0] && call->rtp) {
        struct codec_tag tags[MAX_CODEC_TAGS];
        int tag_count = codec_tags_from_string(codec_tags, tags, MAX_CODEC_TAGS);
        if (tag_count > 0) {
            build_sdp_body(sdp_body, sizeof(sdp_body), call->rtp, s->listen_addr, tags, tag_count);
            sdp_len = (int)strlen(sdp_body);
        }
    }

    char ringing[1024];
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
        call->trunk_via  ? call->trunk_via  : "",
        call->trunk_from ? call->trunk_from : "",
        call->trunk_to   ? call->trunk_to   : "",
        call->sip_call_id,
        call->cseq_num,
        sdp_len > 0 ? "Content-Type: application/sdp\r\n" : "",
        sdp_len,
        sdp_len > 0 ? sdp_body : "");

    send_sip(call->trunk_fd, &call->trunk_addr, ringing, rlen);
    log_info("trunk: sent 180 Ringing to provider for %s", call_id);
}

void trunk_on_backbone_answer(struct trunk_state *s, const char *call_id,
                             const char *codec_tags) {
    struct trunk_call *call = call_lookup(s->calls, call_id);
    if (!call) return;

    call->state = CALL_ACTIVE;

    char sdp_body[2048] = {0};
    int sdp_len = 0;
    if (codec_tags && codec_tags[0] && call->rtp) {
        struct codec_tag tags[MAX_CODEC_TAGS];
        int tag_count = codec_tags_from_string(codec_tags, tags, MAX_CODEC_TAGS);
        if (tag_count > 0) {
            build_sdp_body(sdp_body, sizeof(sdp_body), call->rtp, s->listen_addr, tags, tag_count);
            sdp_len = (int)strlen(sdp_body);
        }
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
        "%s"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s",
        call->trunk_via ? call->trunk_via : "",
        call->trunk_from ? call->trunk_from : "",
        call->trunk_to ? call->trunk_to : "",
        call->sip_call_id,
        call->cseq_num,
        s->config->target && s->config->target->username ? s->config->target->username : "",
        s->listen_addr,
        sdp_len > 0 ? "Content-Type: application/sdp\r\n" : "",
        sdp_len,
        sdp_len > 0 ? sdp_body : "");

    send_sip(call->trunk_fd, &call->trunk_addr, resp, rlen);
    log_info("trunk: answered call %s to provider", call_id);
}

void trunk_on_backbone_cancel(struct trunk_state *s, const char *call_id) {
    struct trunk_call *call = call_lookup(s->calls, call_id);
    if (!call) return;

    if (call->delay_active) {
        call->delay_active = 0;
        call->state = CALL_ENDED;
        call_destroy(s->calls, call);
        return;
    }

    if (call->trunk_fd >= 0) {
        const char *host = s->config->target ? s->config->target->host : "0.0.0.0";
        char cancel[512];
        int clen = snprintf(cancel, sizeof(cancel),
            "CANCEL sip:%s@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s;branch=z9hG4bK%s\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:%s@%s>;tag=%s\r\n"
            "To: <sip:%s@%s>\r\n"
            "Call-ID: %s\r\n"
            "CSeq: 1 CANCEL\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            call->trunk_did ? call->trunk_did : "?",
            host,
            s->listen_addr, call->branch,
            call->trunk_cid ? call->trunk_cid : (s->config->target && s->config->target->username ? s->config->target->username : "trunk"),
            s->listen_addr,
            call->from_tag,
            call->trunk_did ? call->trunk_did : "?",
            host,
            call->sip_call_id);
        send_sip(call->trunk_fd, &s->target_addr, cancel, clen);
        log_info("trunk: sent CANCEL to provider for %s", call->call_id);
    }

    call_destroy(s->calls, call);
}

void trunk_on_backbone_media(struct trunk_state *s, const char *call_id,
                             const uint8_t *data, size_t len) {
    struct trunk_call *call = call_lookup(s->calls, call_id);
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

    rtp_send_to_ext(call->rtp, data, len);
}

void trunk_on_backbone_bye(struct trunk_state *s, const char *call_id) {
    struct trunk_call *call = call_lookup(s->calls, call_id);
    if (!call) return;

    if (call->trunk_fd >= 0) {
        char bye[1024];
        int blen;

        const char *host = s->config->target ? s->config->target->host : "0.0.0.0";
        blen = snprintf(bye, sizeof(bye),
            "BYE sip:%s@%s SIP/2.0\r\n"
            "Via: SIP/2.0/UDP %s;branch=z9hG4bKbye%s\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:%s@%s>;tag=%s\r\n"
            "To: %s\r\n"
            "Call-ID: %s\r\n"
            "CSeq: %d BYE\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            call->trunk_did ? call->trunk_did : "?",
            host,
            s->listen_addr, call->branch,
            call->trunk_cid ? call->trunk_cid : (s->config->target && s->config->target->username ? s->config->target->username : "trunk"), s->listen_addr, call->from_tag,
            call->trunk_to ? call->trunk_to : "",
            call->sip_call_id,
            call->cseq_num + 1);
        send_sip(call->trunk_fd, &call->trunk_addr, bye, blen);
        log_info("trunk: sent BYE to provider for %s", call->call_id);
    }

    call_destroy(s->calls, call);
}

struct trunk_state *trunk_create(struct trk_config *cfg) {
    struct trunk_state *ts = calloc(1, sizeof(struct trunk_state));
    if (!ts) return NULL;
    ts->config = cfg;
    ts->sip_fds = NULL;
    strncpy(ts->listen_addr, "0.0.0.0", sizeof(ts->listen_addr) - 1);
    rtp_ctx_init(&ts->rtp_ctx, cfg->rtp_min, cfg->rtp_max);
    ts->calls = mindex_init(call_cmp, call_purge, NULL);
    return ts;
}

void trunk_free(struct trunk_state *ts) {
    if (!ts) return;
    if (ts->sip_task) sched_remove(ts->sip_task);
    if (ts->delay_task) sched_remove(ts->delay_task);
    if (ts->calls) mindex_free(ts->calls);
    free(ts);
}