#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "register/register.h"
#include "trunk/trunk.h"
#include "md5/md5.h"
#include "rxi/log.h"

static int reg_cseq = 1;

static void md5_hexdigest(const char *input, char *out) {
    uint8_t digest[16];
    trk_md5((const uint8_t *)input, strlen(input), digest);
    trk_md5_hex(digest, out);
}

static void send_raw_register(struct trunk_state *ts, const char *authorization) {
    struct trk_backbone *target = ts->config->target;
    if (!target || !target->host) return;

    const char *user = target->username ? target->username : "";
    const char *host = target->host ? target->host : "localhost";
    const char *auth_hdr = authorization ? authorization : "";

    /* Use NAT-detected public address if available, otherwise listen_addr */
    const char *contact_addr;
    if (ts->public_addr[0] && ts->public_port > 0) {
        contact_addr = ts->public_addr;
    } else {
        contact_addr = ts->listen_addr;
    }
    int contact_port = ts->public_port > 0 ? ts->public_port : 0;

    /* Build Via */
    char via[256];
    if (contact_port) {
        snprintf(via, sizeof(via), "SIP/2.0/UDP %s:%d;rport;branch=z9hG4bKreg",
                 contact_addr, contact_port);
    } else {
        snprintf(via, sizeof(via), "SIP/2.0/UDP %s;rport;branch=z9hG4bKreg",
                 contact_addr);
    }

    /* Build Contact */
    char contact[256];
    if (contact_port) {
        snprintf(contact, sizeof(contact), "<sip:%s@%s:%d>", user, contact_addr, contact_port);
    } else {
        snprintf(contact, sizeof(contact), "<sip:%s@%s>", user, contact_addr);
    }

    char buf[2048];
    int off = snprintf(buf, sizeof(buf),
        "REGISTER sip:%s SIP/2.0\r\n"
        "Via: %s\r\n"
        "From: <sip:%s@%s>;tag=trunk-%s\r\n"
        "To: <sip:%s@%s>\r\n"
        "Call-ID: trunk-register@%s\r\n"
        "CSeq: %d REGISTER\r\n"
        "Contact: %s\r\n"
        "User-Agent: upbx-trunk/" TRK_VERSION "\r\n"
        "Expires: 300\r\n"
        "Content-Length: 0\r\n",
        host,
        via,
        user, host, user,
        user, host,
        host,
        reg_cseq,
        contact);
    if (*auth_hdr) off += snprintf(buf + off, sizeof(buf) - off, "%s", auth_hdr);
    snprintf(buf + off, sizeof(buf) - off, "\r\n");

    ssize_t sent = sendto(ts->sip_fds[1], buf, strlen(buf), 0,
                          (struct sockaddr *)&ts->target_addr,
                          ts->target_addrlen);
    if (sent < 0) {
        log_error("register: sendto failed: %s", strerror(errno));
    }
    log_info("register: sent REGISTER%s to %s (%zd bytes)",
             authorization ? " with auth" : "", host, sent);
    log_debug("sip: >>> %s", buf);

    ts->reg_last_send = (int64_t)time(NULL) * 1000;
}

void trunk_send_register(struct trunk_state *ts) {
    reg_cseq++;
    send_raw_register(ts, NULL);
}

void trunk_send_register_auth(struct trunk_state *ts, const char *www_auth) {
    struct trk_backbone *target = ts->config->target;
    if (!target || !target->username || !target->password) return;

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
    snprintf(uri, sizeof(uri), "sip:%s", host);
    char ha2_input[512];
    snprintf(ha2_input, sizeof(ha2_input), "REGISTER:%s", uri);
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

    reg_cseq++;
    send_raw_register(ts, auth_hdr);

    free(realm);
    free(nonce);
}
