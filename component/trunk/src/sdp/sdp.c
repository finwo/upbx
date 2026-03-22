#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "sdp/sdp.h"

struct sdp_info *sdp_parse(const char *body, int len) {
    struct sdp_info *info = calloc(1, sizeof(struct sdp_info));
    if (!info) return NULL;

    const char *p = body;
    const char *end = body + len;
    info->media_type[0] = '\0';

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

        /* m=<type> <port> ... */
        if (!info->m_port && line_len > 8 && line[0] == 'm' && line[1] == '=') {
            if (memcmp(line + 2, "audio ", 6) == 0) {
                const char *cp = line + 8;
                info->m_port = atoi(cp);
                memcpy(info->media_type, "audio", 6);
            } else if (memcmp(line + 2, "video ", 6) == 0) {
                const char *cp = line + 8;
                info->m_port = atoi(cp);
                memcpy(info->media_type, "video", 6);
            }
        }

        /* a=rtpmap:<pt> <name>/<clock_rate> */
        if (line_len > 9 && line[0] == 'a' && line[1] == '=' &&
            memcmp(line + 2, "rtpmap:", 7) == 0 &&
            info->codec_count < MAX_CODEC_TAGS) {
            const char *cp = line + 9; /* after "a=rtpmap:" */
            const char *cend = line + line_len;

            int pt = atoi(cp);
            /* skip digits */
            while (cp < cend && isdigit((unsigned char)*cp)) cp++;
            if (cp < cend && *cp == ' ') cp++;

            /* rest is name/rate — stored as opaque codec string */
            size_t codec_len = (size_t)(cend - cp);
            if (codec_len > 0 && codec_len < sizeof(info->codecs[0].codec)) {
                struct codec_tag *tag = &info->codecs[info->codec_count];
                tag->stream_id = pt;
                memcpy(tag->media_type, info->media_type[0] ? info->media_type : "audio", 16);
                memcpy(tag->codec, cp, codec_len);
                tag->codec[codec_len] = '\0';
                info->codec_count++;
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

    const char *cline_start = NULL, *cline_ip_start = NULL, *cline_ip_end = NULL, *cline_end = NULL;
    const char *mline_start = NULL, *mline_port_start = NULL, *mline_port_end = NULL, *mline_end = NULL;

    const char *scan = body;
    while (scan < end) {
        const char *nl = memchr(scan, '\n', end - scan);
        if (!nl) nl = end;

        size_t line_len = nl - scan;
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

    if (cline_start) {
        size_t n = cline_ip_start - body;
        memcpy(w, r, n); w += n; r += n;
        n = strlen(new_ip);
        memcpy(w, new_ip, n); w += n;
        r += (cline_ip_end - cline_ip_start);
        n = cline_end - cline_ip_end;
        memcpy(w, r, n); w += n; r += n;
    }

    if (mline_start) {
        size_t n = mline_port_start - r;
        memcpy(w, r, n);
        w += n;
        memcpy(w, new_port_str, new_port_len); w += new_port_len;
        r = mline_port_end;
        n = mline_end - mline_port_end;
        memcpy(w, r, n); w += n; r += n;
    }

    size_t remaining = end - r;
    memcpy(w, r, remaining); w += remaining;

    *w = '\0';
    if (out_len) *out_len = (int)(w - out);
    return out;
}

/* ── codec tag helpers ────────────────────────────────────────── */

char *sdp_build_from_codecs(int rtp_port, const char *listen_ip,
                            const char *addr_family,
                            struct codec_tag *tags, int tag_count) {
    if (!tags || tag_count <= 0) return NULL;
    if (!listen_ip) listen_ip = "0.0.0.0";
    if (!addr_family) addr_family = "IP4";

    /* build m= line payload type list */
    char pt_list[256] = {0};
    int pt_len = 0;
    for (int i = 0; i < tag_count; i++) {
        if (tags[i].stream_id >= 0) {
            if (pt_len) pt_list[pt_len++] = ' ';
            pt_len += snprintf(pt_list + pt_len, sizeof(pt_list) - (size_t)pt_len,
                               "%d", tags[i].stream_id);
        }
    }
    /* fallback: generate payload types if none given */
    if (!pt_len) {
        for (int i = 0; i < tag_count; i++) {
            if (i) pt_list[pt_len++] = ' ';
            pt_len += snprintf(pt_list + pt_len, sizeof(pt_list) - (size_t)pt_len,
                               "%d", 96 + i);
            tags[i].stream_id = 96 + i;
        }
    }

    /* build a=rtpmap lines */
    char rtpmaps[2048] = {0};
    int rtpmaps_len = 0;
    for (int i = 0; i < tag_count; i++) {
        if (tags[i].stream_id >= 0) {
            rtpmaps_len += snprintf(rtpmaps + rtpmaps_len, sizeof(rtpmaps) - (size_t)rtpmaps_len,
                                    "a=rtpmap:%d %s\r\n", tags[i].stream_id, tags[i].codec);
        }
    }

    char *sdp = malloc(1024 + sizeof(rtpmaps));
    if (!sdp) return NULL;

    const char *type = tag_count > 0 ? tags[0].media_type : "audio";
    snprintf(sdp, 1024 + sizeof(rtpmaps),
        "v=0\r\n"
        "o=- 0 0 %s %s\r\n"
        "s=session\r\n"
        "c=%s %s\r\n"
        "t=0 0\r\n"
        "m=%s %d RTP/AVP %s\r\n"
        "%s",
        addr_family, listen_ip, addr_family, listen_ip, type, rtp_port, pt_list, rtpmaps);

    return sdp;
}

char *codec_tags_to_string(struct codec_tag *tags, int tag_count) {
    if (!tags || tag_count <= 0) return NULL;

    /* calculate needed size */
    size_t cap = 1;
    for (int i = 0; i < tag_count; i++) {
        if (tags[i].stream_id >= 0)
            cap += 7 + 2 + strlen(tags[i].media_type) + 1 + strlen(tags[i].codec) + 1;
        else
            cap += 7 + strlen(tags[i].media_type) + 1 + strlen(tags[i].codec) + 1;
    }

    char *buf = malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';

    for (int i = 0; i < tag_count; i++) {
        if (i) strcat(buf, " ");
        if (tags[i].stream_id >= 0) {
            char tmp[128];
            snprintf(tmp, sizeof(tmp), "codec=%d:%s:%s",
                     tags[i].stream_id, tags[i].media_type, tags[i].codec);
            strcat(buf, tmp);
        } else {
            char tmp[128];
            snprintf(tmp, sizeof(tmp), "codec=%s:%s",
                     tags[i].media_type, tags[i].codec);
            strcat(buf, tmp);
        }
    }
    return buf;
}

int codec_tags_from_string(const char *str, struct codec_tag *tags, int max_tags) {
    if (!str || !*str || !tags || max_tags <= 0) return 0;

    int count = 0;
    const char *p = str;

    while (*p && count < max_tags) {
        /* skip spaces */
        while (*p == ' ') p++;
        if (!*p) break;

        /* find end of token */
        const char *end = p;
        while (*end && *end != ' ') end++;

        /* look for "codec=" prefix */
        const char *val = p;
        size_t token_len = (size_t)(end - p);
        if (token_len > 6 && memcmp(p, "codec=", 6) == 0) {
            val = p + 6;
            token_len -= 6;
        }

        /* copy value for safe manipulation */
        char tmp[128];
        if (token_len >= sizeof(tmp)) { p = end; continue; }
        memcpy(tmp, val, token_len);
        tmp[token_len] = '\0';

        /* count colons to determine format */
        int colons = 0;
        for (size_t i = 0; i < token_len; i++)
            if (tmp[i] == ':') colons++;

        struct codec_tag *tag = &tags[count];
        memset(tag, 0, sizeof(*tag));
        tag->stream_id = -1;

        char *colon1 = strchr(tmp, ':');
        if (colons == 0) {
            /* codec=PCMU/8000 — codec only */
            strncpy(tag->codec, tmp, sizeof(tag->codec) - 1);
            strncpy(tag->media_type, "audio", sizeof(tag->media_type) - 1);
        } else if (colons == 1) {
            /* codec=audio:PCMU/8000 or codec=0:PCMU/8000 */
            *colon1 = '\0';
            char *colon2 = colon1 + 1;
            if (isdigit((unsigned char)tmp[0])) {
                tag->stream_id = atoi(tmp);
                strncpy(tag->codec, colon2, sizeof(tag->codec) - 1);
                strncpy(tag->media_type, "audio", sizeof(tag->media_type) - 1);
            } else {
                strncpy(tag->media_type, tmp, sizeof(tag->media_type) - 1);
                strncpy(tag->codec, colon2, sizeof(tag->codec) - 1);
            }
        } else {
            /* codec=0:audio:PCMU/8000 */
            *colon1 = '\0';
            char *colon2 = colon1 + 1;
            char *colon3 = strchr(colon2, ':');
            if (colon3) {
                *colon3 = '\0';
                tag->stream_id = atoi(tmp);
                strncpy(tag->media_type, colon2, sizeof(tag->media_type) - 1);
                strncpy(tag->codec, colon3 + 1, sizeof(tag->codec) - 1);
            }
        }

        count++;
        p = end;
    }

    return count;
}
