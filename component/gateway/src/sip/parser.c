#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>
#include "sip/parser.h"

static int match_header(const char *line, const char *name) {
    size_t nlen = strlen(name);
    if (strncasecmp(line, name, nlen) != 0) return 0;
    return line[nlen] == ':' || line[nlen] == ' ' || line[nlen] == '\t';
}

static char *hdr_val(const char *line, size_t line_len, const char *name) {
    size_t nlen = strlen(name);
    const char *p = line + nlen;
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    const char *line_end = line + line_len;
    while (line_end > p && (line_end[-1] == '\r' || line_end[-1] == '\n' || line_end[-1] == ' '))
        line_end--;
    size_t vlen = (size_t)(line_end - p);
    char *val = malloc(vlen + 1);
    memcpy(val, p, vlen);
    val[vlen] = '\0';
    return val;
}

static int hdr_int(const char *line, size_t line_len, const char *name) {
    char *val = hdr_val(line, line_len, name);
    int n = atoi(val);
    free(val);
    return n;
}

enum sip_method sip_parse_method(const char *s) {
    if (strcasecmp(s, "INVITE")   == 0) return SIP_METHOD_INVITE;
    if (strcasecmp(s, "REGISTER") == 0) return SIP_METHOD_REGISTER;
    if (strcasecmp(s, "ACK")      == 0) return SIP_METHOD_ACK;
    if (strcasecmp(s, "BYE")      == 0) return SIP_METHOD_BYE;
    if (strcasecmp(s, "CANCEL")   == 0) return SIP_METHOD_CANCEL;
    if (strcasecmp(s, "OPTIONS")  == 0) return SIP_METHOD_OPTIONS;
    return SIP_METHOD_UNKNOWN;
}

struct sip_msg *sip_parse_request(const char *buf, int len) {
    if (!buf || len < 10) return NULL;

    struct sip_msg *msg = calloc(1, sizeof(struct sip_msg));
    msg->expires = -1;
    msg->content_length = -1;

    const char *end = buf + len;
    const char *p = buf;

    /* parse request/status line */
    const char *eol = memchr(p, '\n', end - p);
    if (!eol) { free(msg); return NULL; }
    size_t line_len = eol - p;

    /* check if response: starts with SIP/2.0 */
    if (line_len >= 8 && memcmp(p, "SIP/2.0 ", 8) == 0) {
        /* Status line: "SIP/2.0 200 OK" — code starts at p+8 */
        msg->status_code = atoi(p + 8);
        const char *sp = memchr(p + 8, ' ', eol - (p + 8));
        if (sp) {
            const char *reason_start = sp + 1;
            while (*reason_start == ' ') reason_start++;
            const char *reason_end = eol;
            while (reason_end > reason_start && (reason_end[-1] == '\r' || reason_end[-1] == ' '))
                reason_end--;
            size_t rlen = reason_end - reason_start;
            msg->reason = malloc(rlen + 1);
            memcpy(msg->reason, reason_start, rlen);
            msg->reason[rlen] = '\0';
        }
    } else {
        /* request line: METHOD URI SIP/2.0 */
        const char *sp1 = memchr(p, ' ', line_len);
        if (!sp1) { free(msg); return NULL; }
        size_t mlen = sp1 - p;
        char method_buf[16];
        if (mlen >= sizeof(method_buf)) mlen = sizeof(method_buf) - 1;
        memcpy(method_buf, p, mlen);
        method_buf[mlen] = '\0';
        msg->method = sip_parse_method(method_buf);
        msg->method_str = strdup(method_buf);

        const char *sp2 = memchr(sp1 + 1, ' ', eol - (sp1 + 1));
        if (!sp2) { free(msg->method_str); free(msg); return NULL; }

        const char *uri_start = sp1 + 1;
        const char *uri_end = sp2;
        while (uri_end > uri_start && uri_end[-1] == ' ') uri_end--;
        size_t ulen = uri_end - uri_start;
        msg->uri = malloc(ulen + 1);
        memcpy(msg->uri, uri_start, ulen);
        msg->uri[ulen] = '\0';
    }

    p = eol + 1;

    /* parse headers */
    while (p < end) {
        eol = memchr(p, '\n', end - p);
        if (!eol) break;
        line_len = eol - p;

        /* blank line = end of headers */
        if (line_len == 0 || (line_len == 1 && p[0] == '\r')) {
            p = eol + 1;
            break;
        }

        /* continuation line: leading whitespace */
        if (p[0] == ' ' || p[0] == '\t') {
            p = eol + 1;
            continue;
        }

        if (match_header(p, "Via")) {
            free(msg->via);
            msg->via = hdr_val(p, line_len, "Via");
        } else if (match_header(p, "From")) {
            free(msg->from);
            msg->from = hdr_val(p, line_len, "From");
        } else if (match_header(p, "To")) {
            free(msg->to);
            msg->to = hdr_val(p, line_len, "To");
        } else if (match_header(p, "Call-ID")) {
            free(msg->call_id);
            msg->call_id = hdr_val(p, line_len, "Call-ID");
        } else if (match_header(p, "CSeq")) {
            char *val = hdr_val(p, line_len, "CSeq");
            /* format: "number METHOD" */
            char *sp = strchr(val, ' ');
            if (sp) {
                msg->cseq_num = atoi(val);
                while (*sp == ' ') sp++;
                const char *meth_end = sp + strlen(sp);
                size_t mlen = meth_end - sp;
                msg->cseq_method = malloc(mlen + 1);
                memcpy(msg->cseq_method, sp, mlen);
                msg->cseq_method[mlen] = '\0';
            }
            free(val);
        } else if (match_header(p, "Contact")) {
            free(msg->contact);
            msg->contact = hdr_val(p, line_len, "Contact");
        } else if (match_header(p, "Authorization")) {
            free(msg->authorization);
            msg->authorization = hdr_val(p, line_len, "Authorization");
        } else if (match_header(p, "WWW-Authenticate")) {
            free(msg->www_authenticate);
            msg->www_authenticate = hdr_val(p, line_len, "WWW-Authenticate");
        } else if (match_header(p, "Expires")) {
            msg->expires = hdr_int(p, line_len, "Expires");
        } else if (match_header(p, "Content-Length")) {
            msg->content_length = hdr_int(p, line_len, "Content-Length");
        } else if (match_header(p, "Content-Type")) {
            free(msg->content_type);
            msg->content_type = hdr_val(p, line_len, "Content-Type");
        }

        p = eol + 1;
    }

    /* body is whatever remains, points into original buffer */
    if (p < end) {
        msg->body = (char *)p;
        msg->body_len = (int)(end - p);
    }

    return msg;
}

void sip_msg_free(struct sip_msg *msg) {
    if (!msg) return;
    free(msg->method_str);
    free(msg->uri);
    free(msg->via);
    free(msg->from);
    free(msg->to);
    free(msg->call_id);
    free(msg->cseq_method);
    free(msg->contact);
    free(msg->authorization);
    free(msg->www_authenticate);
    free(msg->content_type);
    free(msg->reason);
    free(msg);
}

char *sip_extract_uri_user(const char *uri) {
    if (!uri) return NULL;

    /* skip scheme: sip: or sips: */
    const char *p = uri;
    const char *colon = strstr(p, ":");
    if (!colon) return NULL;
    p = colon + 1;

    /* skip leading // if present */
    if (p[0] == '/' && p[1] == '/') p += 2;

    /* find @ to separate user from host */
    const char *at = strchr(p, '@');
    if (!at || at == p) return NULL;

    size_t ulen = at - p;
    char *user = malloc(ulen + 1);
    memcpy(user, p, ulen);
    user[ulen] = '\0';
    return user;
}

char *sip_extract_uri_host(const char *uri) {
    if (!uri) return NULL;

    /* skip scheme */
    const char *p = uri;
    const char *colon = strstr(p, ":");
    if (!colon) return NULL;
    p = colon + 1;

    /* skip // */
    if (p[0] == '/' && p[1] == '/') p += 2;

    /* skip user@ */
    const char *at = strchr(p, '@');
    if (at) p = at + 1;

    /* host ends at :port, ;params, ?params, or end */
    const char *end = p;
    while (*end && *end != ':' && *end != ';' && *end != '?' && *end != '>')
        end++;

    /* if we hit :port, include it */
    if (*end == ':') {
        const char *pe = end + 1;
        while (*pe && isdigit((unsigned char)*pe)) pe++;
        end = pe;
    }

    size_t hlen = end - p;
    if (hlen == 0) return NULL;
    char *host = malloc(hlen + 1);
    memcpy(host, p, hlen);
    host[hlen] = '\0';
    return host;
}

static char *extract_quoted(const char *key, const char *header) {
    const char *p = header;
    while (p) {
        const char *k = strstr(p, key);
        if (!k) return NULL;
        /* make sure it's a standalone key (preceded by space/comma/start) */
        if (k != header && k[-1] != ' ' && k[-1] != ',') {
            p = k + 1;
            continue;
        }
        const char *eq = strchr(k + strlen(key), '=');
        if (!eq) return NULL;
        eq++;
        while (*eq == ' ') eq++;
        if (*eq == '"') {
            eq++;
            const char *qend = strchr(eq, '"');
            if (!qend) return NULL;
            size_t vlen = qend - eq;
            char *val = malloc(vlen + 1);
            memcpy(val, eq, vlen);
            val[vlen] = '\0';
            return val;
        } else {
            /* unquoted value: until comma or end */
            const char *vend = eq;
            while (*vend && *vend != ',' && *vend != ' ') vend++;
            size_t vlen = vend - eq;
            char *val = malloc(vlen + 1);
            memcpy(val, eq, vlen);
            val[vlen] = '\0';
            return val;
        }
    }
    return NULL;
}

struct sip_auth *sip_parse_auth(const char *header) {
    if (!header) return NULL;

    /* skip "Digest " prefix if present */
    const char *p = header;
    if (strncasecmp(p, "Digest ", 7) == 0) p += 7;

    struct sip_auth *auth = calloc(1, sizeof(struct sip_auth));
    auth->username = extract_quoted("username", p);
    auth->realm    = extract_quoted("realm", p);
    auth->nonce    = extract_quoted("nonce", p);
    auth->uri      = extract_quoted("uri", p);
    auth->response = extract_quoted("response", p);

    return auth;
}

void sip_auth_free(struct sip_auth *auth) {
    if (!auth) return;
    free(auth->username);
    free(auth->realm);
    free(auth->nonce);
    free(auth->uri);
    free(auth->response);
    free(auth);
}
