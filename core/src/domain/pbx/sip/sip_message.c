#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "common/util/hex.h"
#include "domain/pbx/sip/sip_message.h"

static int header_name_match(const char *line, size_t line_len, const char *name) {
    size_t nlen = strlen(name);
    if (line_len < nlen + 1) return 0;
    if (line[nlen] != ':') return 0;
    for (size_t i = 0; i < nlen; i++) {
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i])) return 0;
    }
    return 1;
}

int sip_message_parse(const char *buf, size_t len, sip_message_t *out) {
    if (!buf || !out || len < 12) return -1;
    
    memset(out, 0, sizeof(*out));
    out->data = buf;
    out->len = len;
    
    const char *p = buf;
    const char *end = buf + len;
    const char *line_start = p;
    while (p < end && *p != '\r' && *p != '\n') p++;
    size_t first_line_len = (size_t)(p - line_start);
    
    if (first_line_len >= 8 && memcmp(line_start, "SIP/2.0 ", 8) == 0) {
        const char *code_start = line_start + 8;
        if (code_start + 3 <= end && isdigit((unsigned char)code_start[0]) && 
            isdigit((unsigned char)code_start[1]) && isdigit((unsigned char)code_start[2])) {
            out->status_code = (code_start[0] - '0') * 100 + (code_start[1] - '0') * 10 + (code_start[2] - '0');
            const char *reason_start = code_start + 3;
            while (reason_start < p && *reason_start == ' ') reason_start++;
            out->reason = reason_start;
            out->reason_len = (size_t)(p - reason_start);
        }
    } else {
        const char *sp1 = memchr(line_start, ' ', first_line_len);
        if (sp1 && sp1 < p) {
            out->method = line_start;
            out->method_len = (size_t)(sp1 - line_start);
            const char *uri_start = sp1 + 1;
            const char *sp2 = memchr(uri_start, ' ', (size_t)(p - uri_start));
            if (sp2) {
                out->uri = uri_start;
                out->uri_len = (size_t)(sp2 - uri_start);
            }
        }
    }
    
    if (p < end && *p == '\r' && p + 1 < end && *(p + 1) == '\n') p += 2;
    else if (p < end && *p == '\n') p += 1;
    
    size_t header_cap = 64;
    out->headers = malloc(header_cap * sizeof(sip_header_t));
    if (!out->headers) return -1;
    out->header_count = 0;
    
    while (p < end) {
        if (*p == '\r' || *p == '\n') {
            if (*p == '\r' && p + 1 < end && *(p + 1) == '\n') p += 2;
            else p += 1;
            break;
        }
        
        line_start = p;
        while (p < end && *p != '\r' && *p != '\n') p++;
        size_t line_len = (size_t)(p - line_start);
        
        if (line_len == 0) {
            if (*p == '\r' && p + 1 < end && *(p + 1) == '\n') p += 2;
            else if (p < end) p += 1;
            break;
        }
        
        const char *colon = memchr(line_start, ':', line_len);
        if (colon) {
            if (out->header_count >= header_cap) {
                size_t new_cap = header_cap * 2;
                sip_header_t *new_headers = realloc(out->headers, new_cap * sizeof(sip_header_t));
                if (!new_headers) {
                    sip_message_free(out);
                    return -1;
                }
                out->headers = new_headers;
                header_cap = new_cap;
            }
            
            sip_header_t *h = &out->headers[out->header_count++];
            h->name = line_start;
            h->name_len = (size_t)(colon - line_start);
            
            const char *val_start = colon + 1;
            while (val_start < line_start + line_len && (*val_start == ' ' || *val_start == '\t')) val_start++;
            h->value = val_start;
            h->value_len = (size_t)((line_start + line_len) - val_start);
            
            while (h->value_len > 0 && (h->value[h->value_len - 1] == ' ' || h->value[h->value_len - 1] == '\t')) {
                h->value_len--;
            }
        }
        
        if (*p == '\r' && p + 1 < end && *(p + 1) == '\n') p += 2;
        else if (p < end) p += 1;
    }
    
    if (p < end) {
        out->body = p;
        out->body_len = (size_t)(end - p);
    }
    
    return 0;
}

const char *sip_message_header_get(const sip_message_t *msg, const char *name, size_t *value_len) {
    if (!msg || !name) return NULL;
    
    for (size_t i = 0; i < msg->header_count; i++) {
        const sip_header_t *h = &msg->headers[i];
        if (header_name_match(h->name, h->name_len + 1 + h->value_len, name)) {
            if (value_len) *value_len = h->value_len;
            return h->value;
        }
    }
    return NULL;
}

int sip_message_header_get_all(const sip_message_t *msg, const char *name,
                               const char **values, size_t *value_lens, 
                               size_t max_count, size_t *out_count) {
    if (!msg || !name || !out_count) return -1;
    
    *out_count = 0;
    for (size_t i = 0; i < msg->header_count && *out_count < max_count; i++) {
        const sip_header_t *h = &msg->headers[i];
        if (header_name_match(h->name, h->name_len + 1 + h->value_len, name)) {
            values[*out_count] = h->value;
            if (value_lens) value_lens[*out_count] = h->value_len;
            (*out_count)++;
        }
    }
    return 0;
}

int sip_message_header_copy(const sip_message_t *msg, const char *name, char *out, size_t out_size) {
    size_t len;
    const char *val = sip_message_header_get(msg, name, &len);
    if (!val || out_size == 0) return 0;
    size_t n = len < out_size - 1 ? len : out_size - 1;
    memcpy(out, val, n);
    out[n] = '\0';
    return 1;
}

void sip_message_free(sip_message_t *msg) {
    if (msg && msg->headers) {
        free(msg->headers);
        msg->headers = NULL;
    }
}

int sip_is_request(const sip_message_t *msg) {
    return msg && msg->method && msg->method_len > 0;
}

static size_t url_decode_inplace(char *buf, size_t len) {
    size_t wi = 0;
    for (size_t ri = 0; ri < len; ri++) {
        if (buf[ri] == '%' && ri + 2 < len) {
            int hi = hex_char_to_val(buf[ri + 1]);
            int lo = hex_char_to_val(buf[ri + 2]);
            if (hi >= 0 && lo >= 0) {
                buf[wi++] = (char)((hi << 4) | lo);
                ri += 2;
                continue;
            }
        }
        buf[wi++] = buf[ri];
    }
    return wi;
}

int sip_uri_extract_user(const char *uri, size_t uri_len, char *out, size_t out_size) {
    if (!uri || !out || out_size == 0) return 0;
    
    const char *p = uri;
    const char *end = uri + uri_len;
    
    while (p < end && (*p == ' ' || *p == '\t' || *p == '<')) p++;
    
    if (p + 4 <= end && (strncasecmp(p, "sip:", 4) == 0 || strncasecmp(p, "sips:", 5) == 0)) {
        if (strncasecmp(p, "sips:", 5) == 0) p += 5;
        else p += 4;
    }
    
    const char *user_start = p;
    const char *at_pos = NULL;
    while (p < end && *p != ';' && *p != '>' && *p != ' ' && *p != '\r' && *p != '\n') {
        if (*p == '@' && !at_pos) at_pos = p;
        p++;
    }
    
    if (!at_pos) return 0;
    
    size_t user_len = (size_t)(at_pos - user_start);
    if (user_len == 0 || user_len >= out_size) return 0;
    
    memcpy(out, user_start, user_len);
    out[user_len] = '\0';
    
    size_t decoded_len = url_decode_inplace(out, user_len);
    out[decoded_len] = '\0';
    
    char *at_in_decoded = memchr(out, '@', decoded_len);
    if (at_in_decoded) {
        *at_in_decoded = '\0';
    }
    
    return 1;
}

int sip_header_uri_extract_user(const sip_message_t *msg, const char *header_name, char *out, size_t out_size) {
    size_t val_len;
    const char *val = sip_message_header_get(msg, header_name, &val_len);
    if (!val) return 0;
    return sip_uri_extract_user(val, val_len, out, out_size);
}

int sip_uri_extract_host_port(const char *uri, size_t uri_len, char *host_out, size_t host_size, char *port_out, size_t port_size) {
    if (!uri || !host_out || host_size == 0) return 0;
    
    const char *p = uri;
    const char *end = uri + uri_len;
    
    while (p < end && (*p == ' ' || *p == '\t' || *p == '<')) p++;
    
    if (p + 4 <= end && (strncasecmp(p, "sip:", 4) == 0 || strncasecmp(p, "sips:", 5) == 0)) {
        if (strncasecmp(p, "sips:", 5) == 0) p += 5;
        else p += 4;
    }
    
    const char *last_at = NULL;
    const char *uri_end = p;
    while (uri_end < end && *uri_end != ';' && *uri_end != '>' && *uri_end != ' ' && *uri_end != '\r' && *uri_end != '\n') {
        if (*uri_end == '@') last_at = uri_end;
        uri_end++;
    }
    
    if (last_at) p = last_at + 1;
    
    const char *host_start = p;
    while (p < uri_end && *p != ':') p++;
    
    size_t host_len = (size_t)(p - host_start);
    if (host_len == 0 || host_len >= host_size) return 0;
    
    memcpy(host_out, host_start, host_len);
    host_out[host_len] = '\0';
    
    if (port_out && port_size > 0) {
        if (p < uri_end && *p == ':') {
            p++;
            const char *port_start = p;
            while (p < uri_end) p++;
            size_t port_len = (size_t)(p - port_start);
            if (port_len > 0 && port_len < port_size) {
                memcpy(port_out, port_start, port_len);
                port_out[port_len] = '\0';
            } else {
                memcpy(port_out, "5060", 5);
            }
        } else {
            memcpy(port_out, "5060", 5);
        }
    }
    
    return 1;
}
