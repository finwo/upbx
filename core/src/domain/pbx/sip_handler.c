#include "domain/pbx/sip_handler.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/digest_auth.h"
#include "common/resp.h"
#include "domain/config.h"
#include "domain/pbx/group.h"
#include "domain/pbx/nonce.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sip_message.h"
#include "domain/pbx/sip/sip_proto.h"
#include "rxi/log.h"

#define REALM           "upbx"
#define DEFAULT_EXPIRES 300
#define MAX_EXPIRES     3600

static void normalize_ext_number(const char *username, size_t len, char *out, size_t out_size) {
  if (!username || !out || out_size == 0) return;

  size_t copy_len = len < out_size - 1 ? len : out_size - 1;
  memcpy(out, username, copy_len);
  out[copy_len] = '\0';

  for (size_t ri = 0, wi = 0; ri < copy_len; ri++) {
    if (out[ri] == '%' && ri + 2 < copy_len) {
      int hi = 0, lo = 0;
      if (out[ri + 1] >= '0' && out[ri + 1] <= '9')
        hi = out[ri + 1] - '0';
      else if (out[ri + 1] >= 'A' && out[ri + 1] <= 'F')
        hi = out[ri + 1] - 'A' + 10;
      else if (out[ri + 1] >= 'a' && out[ri + 1] <= 'f')
        hi = out[ri + 1] - 'a' + 10;
      else {
        out[wi++] = out[ri];
        continue;
      }

      if (out[ri + 2] >= '0' && out[ri + 2] <= '9')
        lo = out[ri + 2] - '0';
      else if (out[ri + 2] >= 'A' && out[ri + 2] <= 'F')
        lo = out[ri + 2] - 'A' + 10;
      else if (out[ri + 2] >= 'a' && out[ri + 2] <= 'f')
        lo = out[ri + 2] - 'a' + 10;
      else {
        out[wi++] = out[ri];
        continue;
      }

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
  size_t      val_len;
  const char *val = sip_message_header_get(msg, "Expires", &val_len);
  if (val && val_len > 0) {
    char   buf[32];
    size_t n = val_len < sizeof(buf) - 1 ? val_len : sizeof(buf) - 1;
    memcpy(buf, val, n);
    buf[n] = '\0';
    return atoi(buf);
  }

  val = sip_message_header_get(msg, "Contact", &val_len);
  if (val && val_len > 0) {
    const char *p   = val;
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

static int parse_digest_param(const char *val, size_t val_len, const char *key, char *out, size_t out_size) {
  size_t      klen = strlen(key);
  const char *end  = val + val_len;
  const char *p    = val;

  while (p + klen < end) {
    if ((p == val || p[-1] == ',' || p[-1] == ' ') && strncasecmp(p, key, klen) == 0 && p[klen] == '=') {
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

static char *build_401_response(const sip_message_t *req, const char *ext_number, size_t *out_len) {
  char nonce[128];
  nonce_generate(ext_number, nonce, sizeof(nonce));

  char www_auth[512];
  snprintf(www_auth, sizeof(www_auth), "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5", REALM,
           nonce);

  return sip_proto_build_response(req, 401, "Unauthorized", www_auth, NULL, 0, out_len);
}

static resp_object *get_extension_config(const char *number) {
  if (!domain_cfg || !number) return NULL;

  char key[64];
  snprintf(key, sizeof(key), "ext:%s", number);

  resp_object *sec = resp_map_get(domain_cfg, key);
  if (!sec || sec->type != RESPT_ARRAY) return NULL;

  return sec;
}

char *sip_handle_register(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
) {
  (void)registration;

  if (!msg || !sip_is_request(msg)) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len);
  }

  if (msg->method_len != 8 || strncasecmp(msg->method, "REGISTER", 8) != 0) {
    return sip_proto_build_response(msg, 405, "Method Not Allowed", NULL, NULL, 0, response_len);
  }

  char ext_number[128] = "";

  size_t      auth_len;
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
  char realm[128]    = "";
  char nonce[128]    = "";
  char uri[256]      = "";
  char response[64]  = "";
  char cnonce[64]    = "";
  char nc[16]        = "";
  char qop[16]       = "";

  if (auth_len >= 7 && strncasecmp(auth, "Digest ", 7) == 0) {
    const char *val     = auth + 7;
    size_t      val_len = auth_len - 7;

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
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len);
  }

  if (nonce_validate(nonce, ext_number) != 0) {
    log_debug("sip_handler: nonce validation failed for %s", ext_number);
    return build_401_response(msg, ext_number, response_len);
  }

  resp_object *ext_cfg  = get_extension_config(ext_number);
  const char  *password = ext_cfg ? resp_map_get_string(ext_cfg, "secret") : NULL;

  if (!password) {
    log_debug("sip_handler: extension %s not found or no secret", ext_number);
    return build_401_response(msg, ext_number, response_len);
  }

  HASHHEX ha1, ha2, computed_response;
  digest_calc_ha1(ext_number, REALM, password, ha1);
  digest_calc_ha2("REGISTER", uri, ha2);
  digest_calc_response(ha1, nonce, ha2, computed_response);

  if (strcmp(response, (const char *)computed_response) != 0) {
    log_debug("sip_handler: digest mismatch for %s: expected %s got %s", ext_number, computed_response, response);
    return build_401_response(msg, ext_number, response_len);
  }

  registration_t *existing_reg = registration_find(ext_number);
  if (existing_reg) {
    time_t now = time(NULL);
    if (existing_reg->expires_at > 0 && existing_reg->expires_at < now) {
      log_warn("sip_handler: %s sending traffic with expired registration (expired %ld seconds ago)",
               ext_number, (long)(now - existing_reg->expires_at));
    }
  }

  int expires = parse_expires_header(msg);
  if (expires > MAX_EXPIRES) {
    log_info("sip_handler: %s requested Expires=%d, capping to MAX_EXPIRES=%d", ext_number, expires, MAX_EXPIRES);
    expires = MAX_EXPIRES;
  }

  char contact[512] = "";
  sip_message_header_copy(msg, "Contact", contact, sizeof(contact));

  char to_header[512] = "";
  sip_message_header_copy(msg, "To", to_header, sizeof(to_header));

  char pbx_addr[256] = "";
  if (to_header[0]) {
    char port[32];
    sip_uri_extract_host_port(to_header, strlen(to_header), pbx_addr, sizeof(pbx_addr), port, sizeof(port));
  }

  const char *group = group_find_for_extension(ext_number);

  log_info("sip_handler: REGISTER from %s, Contact: %s, PBX addr: %s, Expires: %d, group: %s", ext_number,
           contact[0] ? contact : "(none)", pbx_addr[0] ? pbx_addr : "(none)", expires, group ? group : "(none)");

  if (expires == 0 || contact[0] == '\0') {
    registration_remove(ext_number);
    return sip_proto_build_response(msg, 200, "OK", NULL, NULL, 0, response_len);
  }

  if (registration_add(ext_number, contact, group, pbx_addr[0] ? pbx_addr : NULL, (const struct sockaddr *)remote_addr, listen_fd, expires) != 0) {
    return sip_proto_build_response(msg, 500, "Server Internal Error", NULL, NULL, 0, response_len);
  }

  char contact_resp[600];
  if (contact[0]) {
    snprintf(contact_resp, sizeof(contact_resp), "<%s>;expires=%d", contact, expires);
  } else {
    contact_resp[0] = '\0';
  }

  char *resp = sip_proto_build_response(msg, 200, "OK", contact_resp[0] ? contact_resp : NULL, NULL, 0, response_len);

  log_info("sip_handler: 200 OK to %s, Expires: %d", ext_number, expires);

  return resp;
}
