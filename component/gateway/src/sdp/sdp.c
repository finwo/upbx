#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sdp/sdp.h"

struct sdp_info *sdp_parse(const char *body, int len) {
    struct sdp_info *info = calloc(1, sizeof(struct sdp_info));
    if (!info) return NULL;

    const char *p = body;
    const char *end = body + len;

    while (p < end) {
        const char *nl = memchr(p, '\n', end - p);
        if (!nl) nl = end;

        size_t line_len = nl - p;
        const char *line = p;

        /* strip trailing \r */
        if (line_len > 0 && line[line_len - 1] == '\r') line_len--;

        /* c=IN IP4 <addr> or c=IN IP6 <addr> */
        if (line_len > 2 && line[0] == 'c' && line[1] == '=') {
            const char *cp = line + 2;
            const char *cend = line + line_len;
            /* skip "IN IP4 " or "IN IP6 " */
            if (cp + 7 < cend && memcmp(cp, "IN IP", 5) == 0 &&
                (cp[5] == '4' || cp[5] == '6') && cp[6] == ' ') {
                cp += 7;
                const char *space = memchr(cp, ' ', cend - cp);
                size_t addrlen = space ? (size_t)(space - cp) : (size_t)(cend - cp);
                info->c_addr = malloc(addrlen + 1);
                memcpy(info->c_addr, cp, addrlen);
                info->c_addr[addrlen] = '\0';
            }
        }

        /* m=audio <port> ... */
        if (!info->m_port && line_len > 8 && line[0] == 'm' && line[1] == '=') {
            if (memcmp(line + 2, "audio ", 6) == 0) {
                const char *cp = line + 8;
                const char *cend = line + line_len;
                info->m_port = atoi(cp);
            }
        }

        p = nl + 1;
    }

    return info;
}

void sdp_free(struct sdp_info *info) {
    if (!info) return;
    free(info->c_addr);
    free(info);
}

char *sdp_rewrite(const char *body, int len, const char *new_ip, int new_port, int *out_len) {
    char new_port_str[16];
    int new_port_len = snprintf(new_port_str, sizeof(new_port_str), "%d", new_port);
    if (new_port_len < 0) new_port_len = 0;

    const char *end = body + len;

    /* find c= line and m= line positions and original content lengths */
    const char *cline_start = NULL, *cline_ip_start = NULL, *cline_ip_end = NULL, *cline_end = NULL;
    const char *mline_start = NULL, *mline_port_start = NULL, *mline_port_end = NULL, *mline_end = NULL;

    const char *scan = body;
    while (scan < end) {
        const char *nl = memchr(scan, '\n', end - scan);
        if (!nl) nl = end;

        size_t line_len = nl - scan;
        /* strip trailing \r */
        const char *line = scan;
        size_t lln = line_len;
        if (lln > 0 && line[lln - 1] == '\r') lln--;

        if (!cline_start && lln > 2 && line[0] == 'c' && line[1] == '=') {
            const char *cp = line + 2;
            const char *lend = line + lln;
            if (cp + 7 < lend && memcmp(cp, "IN IP", 5) == 0 &&
                (cp[5] == '4' || cp[5] == '6') && cp[6] == ' ') {
                cline_start = line;
                cline_end = nl;
                cp += 7;
                cline_ip_start = cp;
                const char *space = memchr(cp, ' ', lend - cp);
                cline_ip_end = space ? space : lend;
            }
        }

        if (!mline_start && lln > 8 && line[0] == 'm' && line[1] == '=') {
            if (memcmp(line + 2, "audio ", 6) == 0) {
                mline_start = line;
                mline_end = nl;
                mline_port_start = line + 8;
                const char *space = memchr(mline_port_start, ' ', lln - 8);
                mline_port_end = space ? space : line + lln;
            }
        }

        scan = nl + 1;
    }

    /* calculate output size */
    int new_len = len;

    if (cline_start) {
        new_len -= (int)(cline_ip_end - cline_ip_start);
        new_len += (int)strlen(new_ip);
    }

    if (mline_start) {
        new_len -= (int)(mline_port_end - mline_port_start);
        new_len += new_port_len;
    }

    char *out = malloc(new_len + 1);
    if (!out) return NULL;

    char *w = out;
    const char *r = body;

    /* copy up to c= line, rewrite c= line if found */
    if (cline_start) {
        size_t n = cline_ip_start - body;
        memcpy(w, r, n); w += n; r += n;
        /* write new ip */
        n = strlen(new_ip);
        memcpy(w, new_ip, n); w += n;
        /* skip old ip */
        r += (cline_ip_end - cline_ip_start);
        /* write rest of c= line */
        n = cline_end - cline_ip_end;
        memcpy(w, r, n); w += n; r += n;
    }

    /* copy up to m= line, rewrite m= line if found */
    if (mline_start) {
        size_t n = mline_port_start - r;
        memcpy(w, r, n);
        w += n;
        /* write new port */
        memcpy(w, new_port_str, new_port_len); w += new_port_len;
        /* skip old port */
        r = mline_port_end;
        /* write rest of m= line */
        n = mline_end - mline_port_end;
        memcpy(w, r, n); w += n; r += n;
    }

    /* copy remainder */
    size_t remaining = end - r;
    memcpy(w, r, remaining); w += remaining;

    *w = '\0';
    if (out_len) *out_len = (int)(w - out);
    return out;
}
