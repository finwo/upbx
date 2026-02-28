#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "rxi/log.h"
#include "RespModule/resp.h"
#include "config.h"
#include "common/digest_auth.h"
#include "AppModule/sip/sip_message.h"
#include "AppModule/pbx/sip_handler.h"
#include "AppModule/pbx/registration.h"
#include "AppModule/pbx/nonce.h"

#define REALM "upbx"
#define DEFAULT_EXPIRES 3600

static void normalize_ext_number(const char *username, size_t len, char *out, size_t out_size) {
    if (!username || !out || out_size == 0) return;
    
    size_t copy_len = len < out_size - 1 ? len : out_size - 1;
    memcpy(out, username, copy_len);
    out[copy_len] = '\0';
    
    for (size_t ri = 0, wi = 0; ri < copy_len; ri++) {
        if (out[ri] == '%' && ri + 2 < copy_len) {
            int hi = 0, lo = 0;
            if (out[ri + 1] >= '0' && out[ri + 1] <= '9') hi = out[ri + 1] - '0';
            else if (out[ri + 1] >= 'A' && out[ri + 1] <= 'F') hi = out[ri + 1] - 'A' + 10;
            else if (out[ri + 1] >= 'a' && out[ri + 1] <= 'f') hi = out[ri + 1] - 'a' + 10;
            else { out[wi++] = out[ri]; continue; }
            
            if (out[ri + 2] >= '0' && out[ri + 2] <= '9') lo = out[ri + 2] - '0';
            else if (out[ri + 2] >= 'A' && out[ri + 2] <= 'F') lo = out[ri + 2] - 'A' + 10;
            else if (out[ri + 2] >= 'a' && out[ri + 2] <= 'f') lo = out[ri + 2] - 'a' + 10;
            else { out[wi++] = out[ri]; continue; }
            
            out[wi++] = (char)((hi << 4) | lo);
            ri += 2;
        } else {
            out[wi++] = out[ri];
        }
    }
    
    char *at = strchr(out, '@');
    if (at) *at = '\0';
}

static int parse_expires_header(const sip_message_t *msg) {
    size_t val_len;
    const char *val = sip_message_header_get(msg, "Expires", &val_len);
    if (val && val_len > 0) {
        char buf[32];
        size_t n = val_len < sizeof(buf) - 1 ? val_len : sizeof(buf) - 1;
        memcpy(buf, val, n);
        buf[n] = '\0';
        return atoi(buf);
    }
    
    val = sip_message_header_get(msg, "Contact", &val_len);
    if (val && val_len > 0) {
        const char *p = val;
        const char *end = val + val_len;
        while (p + 8 <= end) {
            if (strncasecmp(p, "expires=", 8) == 0) {
                p += 8;
                return atoi(p);
            }
            p++;
        }
    }
    
    return DEFAULT_EXPIRES;
}

static int parse_digest_param(const char *val, size_t val_len, const char *key, 
                              char *out, size_t out_size) {
    size_t klen = strlen(key);
    const char *end = val + val_len;
    const char *p = val;
    
    while (p + klen < end) {
        if ((p == val || p[-1] == ',' || p[-1] == ' ') &&
            strncasecmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            if (p >= end) return 0;
            
            if (*p == '"') {
                p++;
                const char *q = p;
                while (q < end && *q != '"') q++;
                size_t len = (size_t)(q - p);
                if (len >= out_size) len = out_size - 1;
                memcpy(out, p, len);
                out[len] = '\0';
                return 1;
            }
            
            const char *q = p;
            while (q < end && *q != ',' && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n') q++;
            size_t len = (size_t)(q - p);
            if (len >= out_size) len = out_size - 1;
            memcpy(out, p, len);
            out[len] = '\0';
            return 1;
        }
        p++;
    }
    return 0;
}

static char *build_response(int status_code, const char *reason,
                            const sip_message_t *req,
                            const char *www_authenticate,
                            const char *contact,
                            size_t *out_len) {
    size_t cap = 4096;
    char *resp = malloc(cap);
    if (!resp) return NULL;
    
    size_t used = 0;
    int n;
    
    n = snprintf(resp + used, cap - used, "SIP/2.0 %d %s\r\n", status_code, reason);
    if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
    used += (size_t)n;
    
    size_t via_len;
    const char *via = sip_message_header_get(req, "Via", &via_len);
    if (via && via_len > 0) {
        n = snprintf(resp + used, cap - used, "Via: %.*s\r\n", (int)via_len, via);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t from_len;
    const char *from = sip_message_header_get(req, "From", &from_len);
    if (from && from_len > 0) {
        n = snprintf(resp + used, cap - used, "From: %.*s\r\n", (int)from_len, from);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t to_len;
    const char *to = sip_message_header_get(req, "To", &to_len);
    if (to && to_len > 0) {
        n = snprintf(resp + used, cap - used, "To: %.*s\r\n", (int)to_len, to);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t call_id_len;
    const char *call_id = sip_message_header_get(req, "Call-ID", &call_id_len);
    if (call_id && call_id_len > 0) {
        n = snprintf(resp + used, cap - used, "Call-ID: %.*s\r\n", (int)call_id_len, call_id);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    size_t cseq_len;
    const char *cseq = sip_message_header_get(req, "CSeq", &cseq_len);
    if (cseq && cseq_len > 0) {
        n = snprintf(resp + used, cap - used, "CSeq: %.*s\r\n", (int)cseq_len, cseq);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    if (contact && contact[0]) {
        n = snprintf(resp + used, cap - used, "Contact: %s\r\n", contact);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    if (www_authenticate && www_authenticate[0]) {
        n = snprintf(resp + used, cap - used, "%s\r\n", www_authenticate);
        if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
        used += (size_t)n;
    }
    
    n = snprintf(resp + used, cap - used, "Content-Length: 0\r\n\r\n");
    if (n < 0 || (size_t)n >= cap - used) { free(resp); return NULL; }
    used += (size_t)n;
    
    if (out_len) *out_len = used;
    return resp;
}

static char *build_401_response(const sip_message_t *req, const char *ext_number,
                                size_t *out_len) {
    char nonce[128];
    nonce_generate(ext_number, nonce, sizeof(nonce));
    
    char www_auth[512];
    snprintf(www_auth, sizeof(www_auth), 
             "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5",
             REALM, nonce);
    
    return build_response(401, "Unauthorized", req, www_auth, NULL, out_len);
}

static resp_object *get_extension_config(const char *number) {
    if (!global_cfg || !number) return NULL;
    
    char key[64];
    snprintf(key, sizeof(key), "ext:%s", number);
    
    resp_object *sec = resp_map_get(global_cfg, key);
    if (!sec || sec->type != RESPT_ARRAY) return NULL;
    
    return sec;
}

char *sip_handle_register(sip_message_t *msg,
                          const struct sockaddr_storage *remote_addr,
                          size_t *response_len) {
    if (!msg || !sip_is_request(msg)) {
        return build_response(400, "Bad Request", msg, NULL, NULL, response_len);
    }
    
    if (msg->method_len != 8 || strncasecmp(msg->method, "REGISTER", 8) != 0) {
        return build_response(405, "Method Not Allowed", msg, NULL, NULL, response_len);
    }
    
    char ext_number[128] = "";
    
    size_t auth_len;
    const char *auth = sip_message_header_get(msg, "Authorization", &auth_len);
    
    if (!auth || auth_len == 0) {
        if (sip_header_uri_extract_user(msg, "To", ext_number, sizeof(ext_number))) {
            return build_401_response(msg, ext_number, response_len);
        }
        if (msg->uri && msg->uri_len > 0) {
            sip_uri_extract_user(msg->uri, msg->uri_len, ext_number, sizeof(ext_number));
        }
        return build_401_response(msg, ext_number[0] ? ext_number : "unknown", response_len);
    }
    
    char username[128] = "";
    char realm[128] = "";
    char nonce[128] = "";
    char uri[256] = "";
    char response[64] = "";
    char cnonce[64] = "";
    char nc[16] = "";
    char qop[16] = "";
    
    if (auth_len >= 7 && strncasecmp(auth, "Digest ", 7) == 0) {
        const char *val = auth + 7;
        size_t val_len = auth_len - 7;
        
        parse_digest_param(val, val_len, "username", username, sizeof(username));
        parse_digest_param(val, val_len, "realm", realm, sizeof(realm));
        parse_digest_param(val, val_len, "nonce", nonce, sizeof(nonce));
        parse_digest_param(val, val_len, "uri", uri, sizeof(uri));
        parse_digest_param(val, val_len, "response", response, sizeof(response));
        parse_digest_param(val, val_len, "cnonce", cnonce, sizeof(cnonce));
        parse_digest_param(val, val_len, "nc", nc, sizeof(nc));
        parse_digest_param(val, val_len, "qop", qop, sizeof(qop));
    }
    
    normalize_ext_number(username, strlen(username), ext_number, sizeof(ext_number));
    
    if (ext_number[0] == '\0') {
        return build_response(400, "Bad Request", msg, NULL, NULL, response_len);
    }
    
    if (nonce_validate(nonce, ext_number) != 0) {
        log_debug("sip_handler: nonce validation failed for %s", ext_number);
        return build_401_response(msg, ext_number, response_len);
    }
    
    resp_object *ext_cfg = get_extension_config(ext_number);
    const char *password = ext_cfg ? resp_map_get_string(ext_cfg, "secret") : NULL;
    
    if (!password) {
        log_debug("sip_handler: extension %s not found or no secret", ext_number);
        return build_401_response(msg, ext_number, response_len);
    }
    
    HASHHEX ha1, computed_response;
    digest_calc_ha1(NULL, ext_number, REALM, password, nonce, cnonce, ha1);
    digest_calc_response(ha1, nonce, nc, cnonce, qop, "REGISTER", uri, NULL, computed_response);
    
    if (strcmp(response, (const char *)computed_response) != 0) {
        log_debug("sip_handler: digest mismatch for %s: expected %s got %s", 
                  ext_number, computed_response, response);
        return build_401_response(msg, ext_number, response_len);
    }
    
    int expires = parse_expires_header(msg);
    
    char contact[512] = "";
    sip_message_header_copy(msg, "Contact", contact, sizeof(contact));
    
    if (expires == 0 || contact[0] == '\0') {
        registration_remove(ext_number);
        return build_response(200, "OK", msg, NULL, NULL, response_len);
    }
    
    if (registration_add(ext_number, contact, (const struct sockaddr *)remote_addr, expires) != 0) {
        return build_response(500, "Server Internal Error", msg, NULL, NULL, response_len);
    }
    
    char contact_resp[600];
    if (contact[0]) {
        snprintf(contact_resp, sizeof(contact_resp), "<%s>", contact);
    } else {
        contact_resp[0] = '\0';
    }
    
    return build_response(200, "OK", msg, NULL, 
                          contact_resp[0] ? contact_resp : NULL, response_len);
}
