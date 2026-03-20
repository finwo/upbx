#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "register/register.h"
#include "sip/parser.h"
#include "md5/md5.h"
#include "rxi/log.h"

static int cseq = 1;

static void md5_hexdigest(const char *input, char *out) {
    uint8_t digest[16];
    trk_md5((const uint8_t *)input, strlen(input), digest);
    trk_md5_hex(digest, out);
}

static void build_sip_register(struct register_state *rs, char *buf, size_t bufsz,
                               const char *authorization) {
    struct trk_backbone *target = rs->config->target;
    const char *user = target->username ? target->username : "";
    const char *host = target->host ? target->host : "localhost";
    const char *auth_hdr = authorization ? authorization : "";

    int len = snprintf(buf, bufsz,
        "REGISTER sip:%s SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s;branch=z9hG4bKreg\r\n"
        "From: <sip:%s@%s>\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: trunk-register@%s\r\n"
        "CSeq: %d REGISTER\r\n"
        "Contact: <sip:%s@%s>\r\n"
        "User-Agent: upbx-trunk/" TRK_VERSION "\r\n"
        "Expires: 300\r\n"
        "Content-Length: 0\r\n"
        "%s"
        "\r\n",
        host,
        "0.0.0.0",
        user, host,
        user, host,
        host,
        cseq,
        user, "0.0.0.0",
        auth_hdr);
    (void)len;
}

static void resolve_target(struct trk_backbone *target, struct sockaddr_storage *addr) {
    memset(addr, 0, sizeof(*addr));
    struct sockaddr_in *a = (struct sockaddr_in *)addr;
    a->sin_family = AF_INET;
    a->sin_port = htons((uint16_t)(target->port ? atoi(target->port) : 5060));

    if (!target->host) return;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(target->host, NULL, &hints, &res) == 0 && res) {
        memcpy(a, res->ai_addr, sizeof(*a));
        a->sin_port = htons((uint16_t)(target->port ? atoi(target->port) : 5060));
        freeaddrinfo(res);
    }
}

static void send_register(struct register_state *rs) {
    struct trk_backbone *target = rs->config->target;
    if (!target || !target->host) return;

    char buf[2048];
    build_sip_register(rs, buf, sizeof(buf), NULL);

    struct sockaddr_storage dst;
    resolve_target(target, &dst);

    ssize_t sent = sendto(rs->fd, buf, strlen(buf), 0, (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) {
        log_error("register: sendto failed: %s", strerror(errno));
    }
    log_info("register: sent REGISTER to %s (%zd bytes)", target->host, sent);
    log_debug("sip: >>> %s", buf);

    rs->last_register = (int64_t)time(NULL) * 1000;
}

static void send_register_auth(struct register_state *rs, const char *www_auth) {
    struct trk_backbone *target = rs->config->target;
    if (!target || !target->host || !target->username || !target->password) return;

    /* Parse the auth challenge */
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

    /* HA2 = md5(METHOD:uri) */
    char uri[256];
    snprintf(uri, sizeof(uri), "sip:%s", host);
    char ha2_input[512];
    snprintf(ha2_input, sizeof(ha2_input), "REGISTER:%s", uri);
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

    cseq++;
    char buf[2048];
    build_sip_register(rs, buf, sizeof(buf), auth_hdr);

    struct sockaddr_storage dst;
    resolve_target(target, &dst);

    ssize_t sent = sendto(rs->fd, buf, strlen(buf), 0, (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0) {
        log_error("register: sendto failed: %s", strerror(errno));
    }
    log_info("register: sent REGISTER with auth to %s (%zd bytes)", host, sent);
    log_debug("sip: >>> %s", buf);

    rs->last_register = (int64_t)time(NULL) * 1000;

    free(realm);
    free(nonce);
}

static int register_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct register_state *rs = pt->udata;
    int64_t now_ms = (int64_t)time(NULL) * 1000;

    if (rs->registered) {
        /* Re-register well before expiry */
        int re_reg_ms = (rs->expires > 60) ? (rs->expires - 60) * 1000 : rs->expires * 500;
        if (now_ms - rs->last_register >= re_reg_ms) {
            rs->registered = 0;
            cseq++;
            send_register(rs);
        }
    } else if (rs->last_register == 0) {
        /* Initial register */
        send_register(rs);
    } else if (now_ms - rs->last_register > 30000) {
        /* No response in 30s, retry */
        cseq++;
        send_register(rs);
    }

    return SCHED_RUNNING;
}

void register_on_401(struct register_state *rs, const char *www_auth) {
    log_info("register: received 401, authenticating");
    send_register_auth(rs, www_auth);
}

void register_on_200(struct register_state *rs, int expires) {
    rs->registered = 1;
    rs->expires = expires > 0 ? expires : 300;
    log_info("register: registered with upstream, expires=%d", rs->expires);
}

struct register_state *register_create(struct trk_config *cfg, struct trunk_state *trunk, int fd) {
    struct register_state *rs = calloc(1, sizeof(*rs));
    if (!rs) return NULL;
    rs->config = cfg;
    rs->trunk = trunk;
    rs->fd = fd;
    rs->registered = 0;
    rs->last_register = 0;
    rs->expires = 300;

    rs->task = sched_create(register_task, rs);
    if (!rs->task) { free(rs); return NULL; }

    return rs;
}

void register_free(struct register_state *rs) {
    if (!rs) return;
    if (rs->task) sched_remove(rs->task);
    free(rs);
}
