#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sip/parser.h"

char *sip_build_response(int code, const char *reason,
                         struct sip_msg *orig,
                         const char *extra_headers,
                         const char *body, int body_len) {

    int has_body = (body && body_len > 0);
    int cl = has_body ? body_len : 0;

    /* compute extra headers length */
    size_t ehlen = extra_headers ? strlen(extra_headers) : 0;

    /* estimate size */
    size_t cap = 1024 + ehlen + cl;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    int off = 0;

    off += snprintf(buf + off, cap - off, "SIP/2.0 %d %s\r\n", code, reason);
    if (orig->via)
        off += snprintf(buf + off, cap - off, "Via: %s\r\n", orig->via);
    if (orig->from)
        off += snprintf(buf + off, cap - off, "From: %s\r\n", orig->from);
    if (orig->to)
        off += snprintf(buf + off, cap - off, "To: %s\r\n", orig->to);
    if (orig->call_id)
        off += snprintf(buf + off, cap - off, "Call-ID: %s\r\n", orig->call_id);
    if (orig->cseq_num > 0 && orig->cseq_method)
        off += snprintf(buf + off, cap - off, "CSeq: %d %s\r\n", orig->cseq_num, orig->cseq_method);

    off += snprintf(buf + off, cap - off, "Content-Length: %d\r\n", cl);

    if (ehlen > 0) {
        off += snprintf(buf + off, cap - off, "%s", extra_headers);
    }

    off += snprintf(buf + off, cap - off, "\r\n");

    if (has_body) {
        memcpy(buf + off, body, body_len);
        off += body_len;
    }

    buf[off] = '\0';
    return buf;
}

char *sip_build_401(struct sip_msg *orig, const char *nonce, const char *realm) {
    char hdr[1024];
    snprintf(hdr, sizeof(hdr),
             "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5\r\n",
             realm, nonce);
    return sip_build_response(401, "Unauthorized", orig, hdr, NULL, 0);
}
