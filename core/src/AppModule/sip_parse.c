/*
 * SIP parse helpers: security_check_raw, in-place fixup, and minimal response parser (no libosip2).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "AppModule/sip_parse.h"
#include "AppModule/pbx/registration.h"
#include "AppModule/pbx/call.h"
#include "common/hexdump.h"
#include "config.h"
#include "common/digest_auth.h"
#include "RespModule/resp.h"

#define SEC_MINLEN      16
#define SEC_MAXLINELEN  2048
#define SIP_MAX_HEADERS (32 * 1024)

bool looks_like_sip(const char *buf, size_t len) {
  log_trace("%s", __func__);
  if (len < 12)
    return false;
  size_t max = len < SIP_MAX_HEADERS ? len : SIP_MAX_HEADERS;
  for (size_t i = 0; i + 3 < max; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
      return true;
  }
  return false;
}

/* Raw security checks before osip_message_parse. */
int sip_security_check_raw(char *sip_buffer, size_t size) {
  char *p1, *p2;

  if (size < SEC_MINLEN)
    return 0;

  for (p1 = sip_buffer; (p1 + SEC_MAXLINELEN) < (sip_buffer + size); p1 = p2 + 1) {
    p2 = strchr(p1, '\n');
    if (!p2 || (size_t)(p2 - p1) > SEC_MAXLINELEN)
      return 0;
  }

  p1 = strchr(sip_buffer, ' ');
  if (!p1 || (p1 + 1) >= (sip_buffer + size))
    return 0;
  p2 = strchr(p1 + 1, ' ');
  if (!p2)
    return 0;

  if (size > 20) {
    char method[16] = {0};
    char proto[16] = {0};
    if (sscanf(sip_buffer, "%15s %*s %15s", method, proto) == 2) {
      if ((strcmp(method, "INVITE") == 0 || strcmp(method, "ACK") == 0 ||
           strcmp(method, "BYE") == 0 || strcmp(method, "CANCEL") == 0 ||
           strcmp(method, "REGISTER") == 0 || strcmp(method, "OPTIONS") == 0 ||
           strcmp(method, "INFO") == 0) && strcmp(proto, "SIP/2.0") == 0) {
        return 0;
      }
      if (strcmp(proto, "SIP/2.0") == 0) return 0;
    }
  }

  return 1;
}

static int header_name_match(const char *line, size_t line_len, const char *name) {
  size_t nlen = strlen(name);
  if (line_len < nlen + 1 || line[nlen] != ':') return 0;
  for (size_t i = 0; i < nlen; i++) {
    if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i])) return 0;
  }
  return 1;
}

int sip_response_status_code(const char *buf, size_t len) {
  if (len < 12 || memcmp(buf, "SIP/2.0 ", 8) != 0) return 0;
  const char *p = buf + 8;
  size_t rem = len - 8;
  if (rem < 4) return 0;
  if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]) || !isdigit((unsigned char)p[2]))
    return 0;
  return (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
}

int sip_response_reason_phrase(const char *buf, size_t len, char *out, size_t out_size) {
  if (len < 12 || memcmp(buf, "SIP/2.0 ", 8) != 0 || out_size == 0) return 0;
  const char *p = buf + 8;
  if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]) || !isdigit((unsigned char)p[2]) || p[3] != ' ')
    return 0;
  p += 4; /* after "NNN " */
  const char *start = p;
  while (p < buf + len && *p != '\r' && *p != '\n') p++;
  size_t n = (size_t)(p - start);
  if (n >= out_size) n = out_size - 1;
  memcpy(out, start, n);
  out[n] = '\0';
  return 1;
}

int sip_header_get(const char *buf, size_t len, const char *name, const char **value_out, size_t *value_len_out) {
  const char *p = buf;
  const char *end = buf + len;
  const char *line_start;
  size_t name_len = strlen(name);

  /* Skip status line */
  while (p < end && *p != '\r' && *p != '\n') p++;
  if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
  else if (p < end && *p == '\n') p += 1;

  while (p < end) {
    line_start = p;
    while (p < end && *p != '\r' && *p != '\n') p++;
    if (line_start == p) break; /* blank line */
    if (p - line_start >= name_len + 1 && line_start[name_len] == ':' &&
        header_name_match(line_start, (size_t)(p - line_start), name)) {
      const char *val = line_start + name_len + 1;
      while (val < p && (*val == ' ' || *val == '\t')) val++;
      *value_out = val;
      *value_len_out = (size_t)(p - val);
      /* RFC 3261: unfold continuation lines (\r\n followed by LWS) into this header value */
      while (p + 2 < end && p[0] == '\r' && p[1] == '\n' && (p[2] == ' ' || p[2] == '\t')) {
        p += 2;
        while (p < end && *p != '\r' && *p != '\n') p++;
        *value_len_out = (size_t)(p - (*value_out));
      }
      /* Trim trailing LWS so Call-ID and other headers match consistently (no in-place change). */
      while (*value_len_out > 0 && ((*value_out)[*value_len_out - 1] == ' ' || (*value_out)[*value_len_out - 1] == '\t'))
        *value_len_out -= 1;
      return 1;
    }
    if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
    else if (p < end) p += 1;
  }
  return 0;
}

int sip_header_copy(const char *buf, size_t len, const char *name, char *out, size_t out_size) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, name, &val, &val_len) || out_size == 0) return 0;
  size_t n = val_len < out_size - 1 ? val_len : out_size - 1;
  memcpy(out, val, n);
  out[n] = '\0';
  return 1;
}

/* Parse token=value or token="value" from a header value; value_out is malloc'd, caller frees. */
static int parse_digest_param(const char *val, size_t val_len, const char *key, char **value_out) {
  size_t klen = strlen(key);
  const char *end = val + val_len;
  const char *p = val;
  while (p + klen < end) {
    if ((p == val || p[-1] == ',' || p[-1] == ' ') &&
        memcmp(p, key, klen) == 0 && p[klen] == '=') {
      p += klen + 1;
      while (p < end && (*p == ' ' || *p == '\t')) p++;
      if (p >= end) return 0;
      if (*p == '"') {
        const char *q = ++p;
        while (q < end && *q != '"') q++;
        if (q >= end) return 0;
        size_t len = (size_t)(q - p);
        *value_out = malloc(len + 1);
        if (!*value_out) return 0;
        memcpy(*value_out, p, len);
        (*value_out)[len] = '\0';
        return 1;
      }
      { const char *q = p;
        while (q < end && *q != ',' && *q != ' ' && *q != '\t' && *q != '\r' && *q != '\n') q++;
        size_t len = (size_t)(q - p);
        *value_out = malloc(len + 1);
        if (!*value_out) return 0;
        memcpy(*value_out, p, len);
        (*value_out)[len] = '\0';
        return 1;
      }
    }
    p++;
  }
  return 0;
}

int sip_parse_www_authenticate(const char *buf, size_t len, char **nonce_out, char **realm_out,
    char **algorithm_out, char **opaque_out, char **qop_out) {
  const char *val;
  size_t val_len;
  *nonce_out = NULL;
  *realm_out = NULL;
  if (algorithm_out) *algorithm_out = NULL;
  if (opaque_out) *opaque_out = NULL;
  if (qop_out) *qop_out = NULL;
  if (!sip_header_get(buf, len, "WWW-Authenticate", &val, &val_len)) return 0;
  if (val_len < 7 || strncasecmp(val, "Digest ", 7) != 0) return 0;
  val += 7; val_len -= 7;
  if (!parse_digest_param(val, val_len, "nonce", nonce_out)) return 0;
  if (!parse_digest_param(val, val_len, "realm", realm_out)) {
    free(*nonce_out);
    *nonce_out = NULL;
    return 0;
  }
  if (algorithm_out)
    parse_digest_param(val, val_len, "algorithm", algorithm_out);
  if (opaque_out)
    parse_digest_param(val, val_len, "opaque", opaque_out);
  if (qop_out)
    parse_digest_param(val, val_len, "qop", qop_out);
  return 1;
}

static int parse_expires_value(const char *val, size_t val_len) {
  const char *p = val;
  const char *end = val + val_len;
  for (; p + 8 <= end; p++) {
    if (strncasecmp(p, "expires=", 8) != 0) continue;
    p += 8;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p < end && isdigit((unsigned char)*p)) return atoi(p);
    return 0;
  }
  return 0;
}

int sip_response_contact_expires(const char *buf, size_t len) {
  const char *val;
  size_t val_len;
  int e;
  if (sip_header_get(buf, len, "Contact", &val, &val_len)) {
    e = parse_expires_value(val, val_len);
    if (e > 0) return e;
  }
  if (sip_header_get(buf, len, "Expires", &val, &val_len) && val_len > 0) {
    e = atoi(val);
    if (e > 0) return e;
  }
  return 0;
}

/* Request parser (no libosip2) */

/* Return 1 if buf is a SIP request (has method in first line), 0 if response or invalid. */
int sip_is_request(const char *buf, size_t len) {
  if (len < 12) return 0;
  if (memcmp(buf, "SIP/2.0 ", 8) == 0) return 0; /* response */
  const char *p = buf;
  while (p < buf + len && *p != ' ' && *p != '\r' && *p != '\n') p++;
  if (p >= buf + len || *p != ' ') return 0;
  return 1;
}

/* Get method from first line (METHOD uri SIP/2.0). *method_out points into buf. Returns 1 on success. */
int sip_request_method(const char *buf, size_t len, const char **method_out, size_t *method_len_out) {
  if (len < 12 || memcmp(buf, "SIP/2.0 ", 8) == 0) return 0;
  const char *end = buf + len;
  const char *p = buf;
  while (p < end && *p != ' ' && *p != '\r' && *p != '\n') p++;
  if (p >= end || *p != ' ') return 0;
  *method_out = buf;
  *method_len_out = (size_t)(p - buf);
  return 1;
}

/* Copy Request-URI from first line (METHOD REQUEST-URI SIP/2.0). */
int sip_request_uri_get(const char *buf, size_t len, char *out, size_t out_size) {
  if (len < 12 || out_size == 0) return 0;
  const char *end = buf + len;
  const char *p = buf;
  while (p < end && *p != ' ' && *p != '\r' && *p != '\n') p++;
  if (p >= end || *p != ' ') return 0;
  p++;
  const char *start = p;
  while (p < end && *p != ' ' && *p != '\r' && *p != '\n') p++;
  size_t n = (size_t)(p - start);
  if (n == 0 || n >= out_size) return 0;
  memcpy(out, start, n);
  out[n] = '\0';
  return 1;
}

/* Get userinfo from Request-URI (METHOD sip:userinfo@host SIP/2.0). userinfo may contain '@' (e.g. 100@trunkname).
 * Returns full userinfo so caller can strip trunk for extension lookup. Writes to user_out, max user_size. Returns 1 on success. */
int sip_request_uri_user(const char *buf, size_t len, char *user_out, size_t user_size) {
  if (len < 14 || user_size == 0) return 0;
  const char *p = buf;
  while (p < buf + len && *p != ' ') p++;
  if (p >= buf + len) return 0;
  p++;
  if (p + 4 >= buf + len || strncasecmp(p, "sip:", 4) != 0) return 0;
  p += 4;
  const char *start = p;
  const char *last_at = NULL;
  while (p < buf + len && *p != ';' && *p != ' ' && *p != '\r' && *p != '\n') {
    if (*p == '@') last_at = p;
    p++;
  }
  /* userinfo is from start to last_at (exclusive). Require at least one @ so we don't treat sip:host as user. */
  if (!last_at) return 0;
  size_t n = (size_t)(last_at - start);
  if (n == 0 || n >= user_size) return 0;
  memcpy(user_out, start, n);
  user_out[n] = '\0';
  return 1;
}

/* Get host and port from Request-URI (METHOD sip:userinfo@host or sip:userinfo@host:port). userinfo may contain '@'. Returns 1 on success. */
int sip_request_uri_host_port(const char *buf, size_t len, char *host_out, size_t host_size, char *port_out, size_t port_size) {
  if (len < 14 || host_size == 0 || port_size == 0) return 0;
  const char *p = buf;
  while (p < buf + len && *p != ' ') p++;
  if (p >= buf + len) return 0;
  p++;
  if (p + 4 >= buf + len || strncasecmp(p, "sip:", 4) != 0) return 0;
  p += 4;
  /* Skip userinfo (may contain '@'); host starts after the last '@' in the URI. */
  const char *last_at = NULL;
  while (p < buf + len && *p != ';' && *p != ' ' && *p != '\r' && *p != '\n') {
    if (*p == '@') last_at = p;
    p++;
  }
  if (!last_at || last_at + 1 >= buf + len) return 0;
  p = last_at + 1;
  const char *host_start = p;
  while (p < buf + len && *p != ':' && *p != ';' && *p != ' ' && *p != '\r' && *p != '\n') p++;
  size_t host_len = (size_t)(p - host_start);
  if (host_len == 0 || host_len >= host_size) return 0;
  memcpy(host_out, host_start, host_len);
  host_out[host_len] = '\0';
  if (p < buf + len && *p == ':') {
    p++;
    const char *port_start = p;
    while (p < buf + len && *p != ';' && *p != ' ' && *p != '\r' && *p != '\n') p++;
    size_t port_len = (size_t)(p - port_start);
    if (port_len > 0 && port_len < port_size) {
      memcpy(port_out, port_start, port_len);
      port_out[port_len] = '\0';
      return 1;
    }
  }
  if (port_size > 0) { memcpy(port_out, "5060", 5); }
  return 1;
}

/* Parse Authorization: Digest; all *out are malloc'd, caller frees. Any out ptr may be NULL (caller doesn't need that value). Returns 1 if Digest with username,realm,nonce,uri,response. */
int sip_parse_authorization_digest(const char *buf, size_t len,
  char **username_out, char **realm_out, char **nonce_out, char **cnonce_out,
  char **nc_out, char **qop_out, char **uri_out, char **response_out) {
  const char *val;
  size_t val_len;
  if (username_out) *username_out = NULL;
  if (realm_out) *realm_out = NULL;
  if (nonce_out) *nonce_out = NULL;
  if (cnonce_out) *cnonce_out = NULL;
  if (nc_out) *nc_out = NULL;
  if (qop_out) *qop_out = NULL;
  if (uri_out) *uri_out = NULL;
  if (response_out) *response_out = NULL;
  if (!sip_header_get(buf, len, "Authorization", &val, &val_len)) return 0;
  if (val_len < 7 || strncasecmp(val, "Digest ", 7) != 0) return 0;
  val += 7; val_len -= 7;
  while (val_len > 0 && (*val == ' ' || *val == '\t')) { val++; val_len--; }

  char *tmp = malloc(val_len + 1);
  memcpy(tmp, val, val_len);
  tmp[val_len] = '\0';

  resp_object *digest = resp_array_init();
  char *saveptr = NULL;
  char *token = strtok_r(tmp, ",", &saveptr);
  while (token) {
    while (*token == ' ' || *token == '\t') token++;
    char *eq = strchr(token, '=');
    if (eq) {
      *eq = '\0';
      char *key = token;
      char *v = eq + 1;
      while (*v == ' ' || *v == '\t') v++;
      size_t vlen = strlen(v);
      if (vlen >= 2 && v[0] == '"' && v[vlen-1] == '"') {
        v[vlen-1] = '\0';
        v++;
      }
      resp_array_append_bulk(digest, key);
      resp_array_append_bulk(digest, v);
    }
    token = strtok_r(NULL, ",", &saveptr);
  }
  free(tmp);

  const char *username = resp_map_get_string(digest, "username");
  const char *realm = resp_map_get_string(digest, "realm");
  const char *nonce = resp_map_get_string(digest, "nonce");
  const char *uri = resp_map_get_string(digest, "uri");
  const char *response = resp_map_get_string(digest, "response");
  if (!username || !realm || !nonce || !uri || !response) {
    resp_free(digest);
    return 0;
  }
  if (username_out) *username_out = strdup(username);
  if (realm_out) *realm_out = strdup(realm);
  if (nonce_out) *nonce_out = strdup(nonce);
  if (uri_out) *uri_out = strdup(uri);
  if (response_out) *response_out = strdup(response);
  if (cnonce_out) {
    const char *cnonce = resp_map_get_string(digest, "cnonce");
    if (cnonce) *cnonce_out = strdup(cnonce);
  }
  if (nc_out) {
    const char *nc = resp_map_get_string(digest, "nc");
    if (nc) *nc_out = strdup(nc);
  }
  if (qop_out) {
    const char *qop = resp_map_get_string(digest, "qop");
    if (qop) *qop_out = strdup(qop);
  }
  resp_free(digest);
  return 1;
}

/* Get URI userinfo from header value (e.g. From/To): "Name" <sip:userinfo@host> or sip:userinfo@host.
 * userinfo may contain '@' (e.g. 100@trunkname). Returns full userinfo. user_out size is user_size. Returns 1 on success. */
static int header_value_uri_user(const char *val, size_t val_len, char *user_out, size_t user_size) {
  const char *end = val + val_len;
  const char *p = val;
  while (p < end && *p != '<') p++;
  if (p < end) p++;
  if (p + 4 >= end || strncasecmp(p, "sip:", 4) != 0) {
    p = val;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p + 4 >= end || strncasecmp(p, "sip:", 4) != 0) return 0;
  } else {
    /* already advanced past '<' */
  }
  if (p + 4 > end) return 0;
  p += 4;
  const char *start = p;
  const char *last_at = NULL;
  while (p < end && *p != ';' && *p != '>' && *p != ' ' && *p != '\r' && *p != '\n') {
    if (*p == '@') last_at = p;
    p++;
  }
  /* Require at least one @ so we don't treat sip:host as user. */
  if (!last_at) return 0;
  size_t n = (size_t)(last_at - start);
  if (n == 0 || n >= user_size) return 0;
  memcpy(user_out, start, n);
  user_out[n] = '\0';
  return 1;
}

int sip_header_uri_user(const char *buf, size_t len, const char *header_name, char *user_out, size_t user_size) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, header_name, &val, &val_len)) return 0;
  return header_value_uri_user(val, val_len, user_out, user_size);
}

/* Split "host" or "host:port" into host and port. If no ':', port is "5060". Returns 1. */
int sip_parse_host_port(const char *host_port, char *host_out, size_t host_size, char *port_out, size_t port_size) {
  if (!host_port || !host_out || !port_out || host_size == 0 || port_size == 0) return 0;
  const char *colon = strchr(host_port, ':');
  if (colon) {
    size_t hlen = (size_t)(colon - host_port);
    if (hlen >= host_size) { host_out[0] = '\0'; port_out[0] = '\0'; return 0; }
    memcpy(host_out, host_port, hlen);
    host_out[hlen] = '\0';
    size_t plen = strlen(colon + 1);
    if (plen >= port_size) { port_out[0] = '\0'; return 0; }
    memcpy(port_out, colon + 1, plen + 1);
  } else {
    size_t n = strlen(host_port) + 1;
    if (n > host_size) { host_out[0] = '\0'; port_out[0] = '\0'; return 0; }
    memcpy(host_out, host_port, n);
    if (port_size < 5) { port_out[0] = '\0'; return 0; }
    memcpy(port_out, "5060", 5);
  }
  return 1;
}

/* Format Request-URI: sip:user@host or sip:host (user NULL or ""), port omitted if NULL or "5060". out_size > 0. Returns 1. */
int sip_format_request_uri(const char *user, const char *host, const char *port, char *out, size_t out_size) {
  if (!out_size || !host || !host[0]) { if (out_size) out[0] = '\0'; return 0; }
  int n;
  int has_port = (port && port[0] && strcmp(port, "5060") != 0);
  if (user && user[0]) {
    n = snprintf(out, out_size, "sip:%s@%s%s%s", user, host, has_port ? ":" : "", has_port ? port : "");
  } else {
    n = snprintf(out, out_size, "sip:%s%s%s", host, has_port ? ":" : "", has_port ? port : "");
  }
  return (n > 0 && (size_t)n < out_size) ? 1 : 0;
}

/* Wrap URI in angle brackets for To/From when value is already a full URI (e.g. request_uri). */
int sip_wrap_angle_uri(const char *uri, char *out, size_t out_size) {
  if (!out_size || !uri) { if (out_size) out[0] = '\0'; return 0; }
  int n = snprintf(out, out_size, "<%s>", uri);
  return (n > 0 && (size_t)n < out_size) ? 1 : 0;
}

/* Format Contact/From/To value: "<sip:user@host[:port]>". port omitted if NULL or "5060". */
int sip_format_contact_uri_value(const char *user, const char *host, const char *port, char *out, size_t out_size) {
  if (!out_size || !host || !host[0]) { if (out_size) out[0] = '\0'; return 0; }
  int has_port = (port && port[0] && strcmp(port, "5060") != 0);
  int n = snprintf(out, out_size, "<sip:%s@%s%s%s>", user ? user : "", host, has_port ? ":" : "", has_port ? port : "");
  return (n > 0 && (size_t)n < out_size) ? 1 : 0;
}

/* Format From/To value: "\"display\" <sip:user@host[:port]>" or "<sip:user@host[:port]>". display NULL = no display. */
int sip_format_from_to_value(const char *display, const char *user, const char *host, const char *port, char *out, size_t out_size) {
  if (!out_size || !host || !host[0]) { if (out_size) out[0] = '\0'; return 0; }
  int has_port = (port && port[0] && strcmp(port, "5060") != 0);
  int n;
  if (display && display[0])
    n = snprintf(out, out_size, "\"%s\" <sip:%s@%s%s%s>", display, user ? user : "", host, has_port ? ":" : "", has_port ? port : "");
  else
    n = snprintf(out, out_size, "<sip:%s@%s%s%s>", user ? user : "", host, has_port ? ":" : "", has_port ? port : "");
  return (n > 0 && (size_t)n < out_size) ? 1 : 0;
}

/* Build WWW-Authenticate header line for 401 (RFC 2617). Caller frees. Returns NULL on alloc failure. */
char *sip_build_www_authenticate(const char *realm, const char *nonce) {
  if (!realm || !nonce) return NULL;
  char *out = NULL;
  if (asprintf(&out, "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5", realm, nonce) < 0)
    return NULL;
  return out;
}

/* Copy header value up to (not including) first ';', trim trailing LWS. Returns 1 on success. */
int sip_header_value_before_first_param(const char *buf, size_t len, const char *header_name, char *out, size_t out_size) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, header_name, &val, &val_len) || out_size == 0) { if (out_size) out[0] = '\0'; return 0; }
  const char *p = val;
  const char *end = val + val_len;
  while (p < end && *p != ';') p++;
  while (p > val && (p[-1] == ' ' || p[-1] == '\t')) p--;
  size_t n = (size_t)(p - val);
  if (n >= out_size) { out[0] = '\0'; return 0; }
  memcpy(out, val, n);
  out[n] = '\0';
  return 1;
}

/* Get first occurrence of param "name=" in header value; copy value (after '=') into out, NUL-term. Returns 1 if found. */
int sip_header_get_param(const char *buf, size_t len, const char *header_name, const char *param_name, char *out, size_t out_size) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, header_name, &val, &val_len) || out_size == 0) { if (out_size) out[0] = '\0'; return 0; }
  size_t plen = strlen(param_name);
  const char *end = val + val_len;
  const char *p = val;
  while (p + plen + 1 <= end) {
    if ((p == val || p[-1] == ';') && strncasecmp(p, param_name, plen) == 0 && p[plen] == '=') {
      const char *v = p + plen + 1;
      const char *v_end = v;
      while (v_end < end && *v_end != ';' && *v_end != ' ' && *v_end != '\r' && *v_end != '\n' && *v_end != '\t') v_end++;
      size_t n = (size_t)(v_end - v);
      if (n >= out_size) n = out_size - 1;
      memcpy(out, v, n);
      out[n] = '\0';
      return 1;
    }
    while (p < end && *p != ';') p++;
    if (p < end) p++;
  }
  out[0] = '\0';
  return 0;
}

/* Append ";tag=value" to out. out must be NUL-terminated; out_size is full buffer size. Returns 1 on success. */
int sip_append_tag_param(char *out, size_t out_size, const char *tag_value) {
  size_t cur = strlen(out);
  if (!tag_value) return 1;
  int n = snprintf(out + cur, out_size - cur, ";tag=%s", tag_value);
  return (n > 0 && (size_t)n < out_size - cur) ? 1 : 0;
}

/* Build Authorization header value (Digest). response_hex = 32-char MD5 hex. algorithm/opaque NULL = omit. Returns 1 on success. */
int sip_build_authorization_digest_value(const char *user, const char *realm, const char *nonce, const char *uri,
  const char *response_hex, const char *algorithm, const char *opaque, char *out, size_t out_size) {
  if (!out_size || !user || !realm || !nonce || !uri || !response_hex) { if (out_size) out[0] = '\0'; return 0; }
  int n = snprintf(out, out_size,
    "Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\"",
    user, realm, nonce, uri, response_hex);
  if (n < 0 || (size_t)n >= out_size) { if (out_size) out[0] = '\0'; return 0; }
  size_t used = (size_t)n;
  if (algorithm && algorithm[0]) {
    n = snprintf(out + used, out_size - used, ",algorithm=%s", algorithm);
    if (n > 0 && (size_t)n < out_size - used) used += (size_t)n;
  }
  if (opaque && opaque[0]) {
    n = snprintf(out + used, out_size - used, ",opaque=\"%s\"", opaque);
    if (n > 0 && (size_t)n < out_size - used) used += (size_t)n;
  }
  return 1;
}

/* Normalise to Via header value only: strip leading "Via:" (case-insensitive) and LWS. */
static const char *via_value_only(const char *via_line) {
  if (!via_line || !via_line[0]) return via_line;
  const char *p = via_line;
  while (*p == ' ' || *p == '\t') p++;
  if ((p[0] == 'V' || p[0] == 'v') && (p[1] == 'I' || p[1] == 'i') && (p[2] == 'A' || p[2] == 'a') && p[3] == ':') {
    p += 4;
    while (*p == ' ' || *p == '\t') p++;
  }
  return p;
}

/* Build REGISTER request. All args are header values (no "Via: " etc.). auth_value NULL = no Authorization. Caller frees. */
char *sip_build_register_request(const char *request_uri, const char *via_value, const char *to_val, const char *from_val,
  const char *call_id, const char *cseq, const char *contact_val, int expires, int max_forwards, const char *user_agent,
  const char *auth_value, size_t *out_len) {
  size_t cap = 4096;
  char *out = malloc(cap);
  if (!out) return NULL;
  size_t used = 0;
  int n = snprintf(out + used, cap - used, "REGISTER %s SIP/2.0\r\n", request_uri ? request_uri : "");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  if (via_value && via_value[0]) {
    const char *v = via_value_only(via_value);
    n = snprintf(out + used, cap - used, "Via: %s\r\n", v);
    if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
    used += (size_t)n;
  }
  if (to_val && to_val[0])   { n = snprintf(out + used, cap - used, "To: %s\r\n", to_val);   if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (from_val && from_val[0]) { n = snprintf(out + used, cap - used, "From: %s\r\n", from_val); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (call_id && call_id[0]) { n = snprintf(out + used, cap - used, "Call-ID: %s\r\n", call_id); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (cseq && cseq[0])       { n = snprintf(out + used, cap - used, "CSeq: %s\r\n", cseq);       if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (contact_val && contact_val[0]) { n = snprintf(out + used, cap - used, "Contact: %s\r\n", contact_val); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  n = snprintf(out + used, cap - used, "Expires: %d\r\nMax-Forwards: %d\r\n", expires, max_forwards);
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  if (user_agent && user_agent[0]) { n = snprintf(out + used, cap - used, "User-Agent: %s\r\n", user_agent); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (auth_value && auth_value[0]) { n = snprintf(out + used, cap - used, "Authorization: %s\r\n", auth_value); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  n = snprintf(out + used, cap - used, "\r\n");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  if (out_len) *out_len = used;
  char *ret = realloc(out, used + 1);
  if (ret) { ret[used] = '\0'; return ret; }
  out[used] = '\0';
  return out;
}

/* Build response from struct. Caller frees. */
char *sip_build_response(sip_response_t *data, size_t *out_len) {
  size_t cap = 4096;
  if (data->body_len > 0)
    cap += data->body_len;
  char *out = malloc(cap);
  if (!out) return NULL;
  size_t used = 0;
  int n = snprintf(out + used, cap - used, "SIP/2.0 %d %s\r\n",
    data->status_code, data->reason && data->reason[0] ? data->reason : "OK");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  {
    const char *via_val = via_value_only(data->via);
    if (via_val && via_val[0]) {
      n = snprintf(out + used, cap - used, "Via: %s\r\n", via_val);
      if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
      used += (size_t)n;
    }
  }
  if (data->from && data->from[0]) { n = snprintf(out + used, cap - used, "From: %s\r\n", data->from); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (data->to && data->to[0])     { n = snprintf(out + used, cap - used, "To: %s\r\n", data->to);     if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (data->call_id && data->call_id[0])   { n = snprintf(out + used, cap - used, "Call-ID: %s\r\n", data->call_id); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (data->cseq && data->cseq[0]) { n = snprintf(out + used, cap - used, "CSeq: %s\r\n", data->cseq); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (data->contact && data->contact[0]) { n = snprintf(out + used, cap - used, "Contact: %s\r\n", data->contact); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (data->user_agent && data->user_agent[0]) { n = snprintf(out + used, cap - used, "User-Agent: %s\r\n", data->user_agent); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  for (size_t i = 0; i < data->n_extra && data->extra_headers && data->extra_headers[i]; i++) {
    size_t el = strlen(data->extra_headers[i]);
    if (used + el + 2 > cap) break;
    memcpy(out + used, data->extra_headers[i], el);
    used += el;
    out[used++] = '\r'; out[used++] = '\n';
  }

  if (data->body_len > 0) {
    n = snprintf(out + used, cap - used, "Content-Type: application/sdp\r\n");
    if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
    used += (size_t)n;
  }
  n = snprintf(out + used, cap - used, "Content-Length: %zu\r\n", data->body_len);
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  n = snprintf(out + used, cap - used, "\r\n");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  if (data->body_len > 0 && data->body) {
    if (used + data->body_len > cap) { free(out); return NULL; }
    memcpy(out + used, data->body, data->body_len);
    used += data->body_len;
  }
  char *ret = realloc(out, used + 1);
  if (ret) { ret[used] = '\0'; if (out_len) *out_len = used; return ret; }
  out[used] = '\0';
  if (out_len) *out_len = used;
  return out;
}

/* Build response from explicit parts (no copy from request). DEPRECATED: use sip_build_response. */
char *sip_build_response_parts(int status_code, const char *reason,
  const char *via_line, const char *from_val, const char *to_val,
  const char *call_id, const char *cseq_val, const char *contact_val, const char *user_agent,
  const char *body, size_t body_len,
  const char **extra_headers, size_t n_extra, size_t *out_len) {
  sip_response_t data = {
    .status_code = status_code,
    .reason = reason,
    .via = via_line,
    .from = from_val,
    .to = to_val,
    .call_id = call_id,
    .cseq = cseq_val,
    .contact = contact_val,
    .user_agent = user_agent,
    .body = body,
    .body_len = body_len,
    .extra_headers = extra_headers,
    .n_extra = n_extra
  };
  return sip_build_response(&data, out_len);
}

/* Write Via header value only (no "Via: " prefix, no CRLF). Same contract as other header values for sip_build_*_parts. */
int sip_make_via_line(const char *host, const char *port, char *out, size_t out_size) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int n = snprintf(out, out_size, "SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%lx%lx%x",
    host, port, (long)ts.tv_sec, (long)ts.tv_nsec, (unsigned)rand());
  return (n > 0 && (size_t)n < out_size) ? 1 : 0;
}

/* Build SIP request from parts. method and request_uri required. Via/From/To/Call-ID/CSeq/Contact are header values only (no "Via: " etc.). */
char *sip_build_request_parts(const char *method, const char *request_uri,
  const char *via_val, const char *from_val, const char *to_val,
  const char *call_id, const char *cseq_val, const char *contact_val,
  int add_alert_info_for_invite,
  const char *body, size_t body_len, size_t *out_len) {
  size_t cap = 4096;
  if (body_len > 0) cap += body_len;
  char *out = malloc(cap);
  if (!out) return NULL;
  size_t used = 0;
  int n = snprintf(out + used, cap - used, "%s %s SIP/2.0\r\n", method, request_uri);
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  {
    const char *v = via_value_only(via_val);
    if (v && v[0]) {
      n = snprintf(out + used, cap - used, "Via: %s\r\n", v);
      if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
      used += (size_t)n;
    }
  }
  n = snprintf(out + used, cap - used, "Max-Forwards: 70\r\n");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  if (from_val && from_val[0]) { n = snprintf(out + used, cap - used, "From: %s\r\n", from_val); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (to_val && to_val[0])     { n = snprintf(out + used, cap - used, "To: %s\r\n", to_val);     if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (call_id && call_id[0])   { n = snprintf(out + used, cap - used, "Call-ID: %s\r\n", call_id); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (cseq_val && cseq_val[0]) { n = snprintf(out + used, cap - used, "CSeq: %s\r\n", cseq_val); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (contact_val && contact_val[0]) { n = snprintf(out + used, cap - used, "Contact: %s\r\n", contact_val); if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; } used += (size_t)n; }
  if (add_alert_info_for_invite && method && strcmp(method, "INVITE") == 0) {
    n = snprintf(out + used, cap - used, "Alert-Info: Ring\r\n");
    if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
    used += (size_t)n;
  }
  if (body_len > 0) {
    n = snprintf(out + used, cap - used, "Content-Type: application/sdp\r\nContent-Length: %zu\r\n", body_len);
    if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
    used += (size_t)n;
  }
  n = snprintf(out + used, cap - used, "\r\n");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;
  if (body_len > 0 && body) {
    if (used + body_len > cap) { free(out); return NULL; }
    memcpy(out + used, body, body_len);
    used += body_len;
  }
  char *ret = realloc(out, used + 1);
  if (ret) { ret[used] = '\0'; if (out_len) *out_len = used; return ret; }
  out[used] = '\0';
  if (out_len) *out_len = used;
  return out;
}

/* Get body start and length (after \r\n\r\n). Returns 1 if found. */
int sip_request_get_body(const char *buf, size_t len, const char **body_out, size_t *body_len_out) {
  const char *p = buf;
  const char *end = buf + len;
  for (; p + 3 < end; p++) {
    if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
      p += 4;
      *body_out = p;
      *body_len_out = (size_t)(end - p);
      return 1;
    }
    if (*p == '\n' && p + 2 < end && p[1] == '\r' && p[2] == '\n') {
      p += 3;
      *body_out = p;
      *body_len_out = (size_t)(end - p);
      return 1;
    }
  }
  return 0;
}

/* ==== Packet rewrite helpers ====
 *
 * Each function copies buf→out with one targeted modification.
 * Returns new length, or -1 on overflow/error. */

/* Helper: append n bytes from src to out. Returns 0 on success, -1 if it would overflow. */
static int rw_append(char *out, size_t cap, size_t *used, const char *src, size_t n) {
  if (*used + n > cap) return -1;
  memcpy(out + *used, src, n);
  *used += n;
  return 0;
}

/* Helper: find end of first line (before \r\n or \n). */
static const char *rw_first_line_end(const char *buf, size_t len) {
  const char *p = buf;
  while (p < buf + len && *p != '\r' && *p != '\n') p++;
  return p;
}

/* Helper: advance past \r\n or \n. */
static const char *rw_skip_eol(const char *p, const char *end) {
  if (p < end && *p == '\r') p++;
  if (p < end && *p == '\n') p++;
  return p;
}

/* Replace Request-URI: "METHOD <old> SIP/2.0\r\n" → "METHOD <new_uri> SIP/2.0\r\n". */
int sip_rewrite_request_uri(const char *buf, size_t len, const char *new_uri,
                            char *out, size_t out_cap) {
  /* Find the two spaces that delimit the Request-URI on the first line:
   * METHOD<sp>REQUEST-URI<sp>SIP/2.0 */
  const char *end = buf + len;
  const char *sp1 = memchr(buf, ' ', len);
  if (!sp1 || sp1 + 1 >= end) return -1;
  const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(end - sp1 - 1));
  if (!sp2) return -1;

  size_t used = 0;
  /* Copy: "METHOD " */
  if (rw_append(out, out_cap, &used, buf, (size_t)(sp1 + 1 - buf))) return -1;
  /* Write new URI. */
  size_t uri_len = strlen(new_uri);
  if (rw_append(out, out_cap, &used, new_uri, uri_len)) return -1;
  /* Copy: " SIP/2.0\r\n..." (from sp2 onwards). */
  size_t tail = (size_t)(end - sp2);
  if (rw_append(out, out_cap, &used, sp2, tail)) return -1;
  return (int)used;
}

/* Insert "Via: <via_value>\r\n" right after the first line. */
int sip_prepend_via(const char *buf, size_t len, const char *via_value,
                    char *out, size_t out_cap) {
  const char *end = buf + len;
  const char *le  = rw_first_line_end(buf, len);
  const char *after_eol = rw_skip_eol(le, end);

  size_t used = 0;
  /* Copy first line + its EOL. */
  if (rw_append(out, out_cap, &used, buf, (size_t)(after_eol - buf))) return -1;
  /* Insert Via header. */
  int n = snprintf(out + used, out_cap - used, "Via: %s\r\n", via_value);
  if (n < 0 || used + (size_t)n >= out_cap) return -1;
  used += (size_t)n;
  /* Copy rest of the message. */
  size_t rest = (size_t)(end - after_eol);
  if (rw_append(out, out_cap, &used, after_eol, rest)) return -1;
  return (int)used;
}

/* Remove the first Via header line (our Via). */
int sip_strip_top_via(const char *buf, size_t len, char *out, size_t out_cap) {
  const char *end = buf + len;
  const char *p = buf;
  /* Skip first line. */
  const char *le = rw_first_line_end(buf, len);
  p = rw_skip_eol(le, end);

  /* Scan for first "Via:" header. */
  const char *via_start = NULL, *via_end = NULL;
  while (p < end) {
    const char *ls = p;
    const char *ll_end = ls;
    while (ll_end < end && *ll_end != '\r' && *ll_end != '\n') ll_end++;
    size_t ll = (size_t)(ll_end - ls);
    if (ll == 0) { p = rw_skip_eol(ll_end, end); break; } /* blank line = headers done */
    if (!via_start && ll >= 4 &&
        (ls[0] == 'V' || ls[0] == 'v') && (ls[1] == 'I' || ls[1] == 'i') &&
        (ls[2] == 'A' || ls[2] == 'a') && ls[3] == ':') {
      via_start = ls;
      via_end   = rw_skip_eol(ll_end, end);
    }
    p = rw_skip_eol(ll_end, end);
  }
  if (!via_start) {
    /* No Via found; copy verbatim. */
    if (len > out_cap) return -1;
    memcpy(out, buf, len);
    return (int)len;
  }
  size_t used = 0;
  /* Copy everything before the Via line. */
  if (rw_append(out, out_cap, &used, buf, (size_t)(via_start - buf))) return -1;
  /* Skip the Via line, copy everything after. */
  size_t rest = (size_t)(end - via_end);
  if (rw_append(out, out_cap, &used, via_end, rest)) return -1;
  return (int)used;
}

/* Replace the value of the first occurrence of header_name. */
int sip_rewrite_header(const char *buf, size_t len, const char *header_name,
                       const char *new_value, char *out, size_t out_cap) {
  size_t name_len = strlen(header_name);
  const char *end = buf + len;
  const char *p = buf;
  /* Skip first line. */
  const char *le = rw_first_line_end(buf, len);
  p = rw_skip_eol(le, end);

  while (p < end) {
    const char *ls = p;
    const char *ll_end = ls;
    while (ll_end < end && *ll_end != '\r' && *ll_end != '\n') ll_end++;
    size_t ll = (size_t)(ll_end - ls);
    if (ll == 0) break; /* blank line = end of headers */

    /* Case-insensitive match: "Header-Name:" */
    if (ll > name_len && ls[name_len] == ':' &&
        strncasecmp(ls, header_name, name_len) == 0) {
      size_t used = 0;
      /* Copy everything before this line. */
      if (rw_append(out, out_cap, &used, buf, (size_t)(ls - buf))) return -1;
      /* Write replacement: "Header-Name: <new_value>\r\n" */
      int n = snprintf(out + used, out_cap - used, "%s: %s\r\n", header_name, new_value);
      if (n < 0 || used + (size_t)n >= out_cap) return -1;
      used += (size_t)n;
      /* Copy everything after this line. */
      const char *after = rw_skip_eol(ll_end, end);
      size_t rest = (size_t)(end - after);
      if (rw_append(out, out_cap, &used, after, rest)) return -1;
      return (int)used;
    }
    p = rw_skip_eol(ll_end, end);
  }
  /* Header not found; copy verbatim. */
  if (len > out_cap) return -1;
  memcpy(out, buf, len);
  return (int)len;
}

/* Insert a new header line before the header/body separator.
 * If the header already exists, copy verbatim (no duplicate). */
int sip_insert_header(const char *buf, size_t len, const char *header_name,
                      const char *value, char *out, size_t out_cap) {
  size_t name_len = strlen(header_name);
  const char *end = buf + len;
  const char *p = buf;
  /* Skip first line. */
  const char *le = rw_first_line_end(buf, len);
  p = rw_skip_eol(le, end);
  /* Check if header already exists. */
  while (p < end) {
    const char *ls = p;
    const char *ll_end = ls;
    while (ll_end < end && *ll_end != '\r' && *ll_end != '\n') ll_end++;
    size_t ll = (size_t)(ll_end - ls);
    if (ll == 0) break; /* blank line */
    if (ll > name_len && ls[name_len] == ':' &&
        strncasecmp(ls, header_name, name_len) == 0) {
      /* Already exists; copy verbatim. */
      if (len > out_cap) return -1;
      memcpy(out, buf, len);
      return (int)len;
    }
    p = rw_skip_eol(ll_end, end);
  }
  /* p now points at the blank line (or end). Insert header before it. */
  size_t used = 0;
  size_t prefix = (size_t)(p - buf);
  if (rw_append(out, out_cap, &used, buf, prefix)) return -1;
  int n = snprintf(out + used, out_cap - used, "%s: %s\r\n", header_name, value);
  if (n < 0 || used + (size_t)n >= out_cap) return -1;
  used += (size_t)n;
  size_t rest = (size_t)(end - p);
  if (rw_append(out, out_cap, &used, p, rest)) return -1;
  return (int)used;
}

/* Replace message body and update Content-Length (+ Content-Type). */
int sip_rewrite_body(const char *buf, size_t len,
                     const char *new_body, size_t new_body_len,
                     char *out, size_t out_cap) {
  /* Find the header/body separator (\r\n\r\n). */
  const char *sep = NULL;
  for (const char *p = buf; p + 3 < buf + len; p++) {
    if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
      sep = p;
      break;
    }
  }
  if (!sep) {
    /* No separator found; treat entire message as headers, append body. */
    sep = buf + len;
  }

  /* Copy headers up to (but not including) the separator, skipping existing
   * Content-Length and Content-Type lines (we'll rewrite them).
   * Use sep+2 as the scan limit so the last header's trailing \r\n is
   * included (sep points at the first \r of \r\n\r\n). */
  size_t used = 0;
  const char *hdr_end = (sep < buf + len) ? sep + 2 : sep;
  const char *p = buf;
  while (p < hdr_end) {
    const char *ls = p;
    const char *le = ls;
    while (le < hdr_end && *le != '\r' && *le != '\n') le++;
    size_t ll = (size_t)(le - ls);
    if (ll == 0) break; /* blank line = header/body boundary */
    const char *after = rw_skip_eol(le, hdr_end);

    /* Skip Content-Length and Content-Type headers. */
    if ((ll >= 15 && strncasecmp(ls, "Content-Length:", 15) == 0) ||
        (ll >= 13 && strncasecmp(ls, "Content-Type:",  13) == 0)) {
      p = after;
      continue;
    }
    if (rw_append(out, out_cap, &used, ls, (size_t)(after - ls))) return -1;
    p = after;
  }

  /* Append Content-Type + Content-Length + blank line + body. */
  int n;
  if (new_body && new_body_len > 0) {
    n = snprintf(out + used, out_cap - used,
                 "Content-Type: application/sdp\r\n"
                 "Content-Length: %zu\r\n\r\n",
                 new_body_len);
  } else {
    n = snprintf(out + used, out_cap - used,
                 "Content-Length: 0\r\n\r\n");
  }
  if (n < 0 || used + (size_t)n >= out_cap) return -1;
  used += (size_t)n;

  if (new_body && new_body_len > 0) {
    if (rw_append(out, out_cap, &used, new_body, new_body_len)) return -1;
  }
  return (int)used;
}

typedef struct {
  const char *buf;
  size_t len;
  char method[16];
  char uri[256];
  char via[512];
  char from[512];
  char to[512];
  char contact[512];
  char call_id[128];
  char cseq[32];
  int expires;
} sip_request_parsed_t;

static int sip_parse_request_line(const char *buf, size_t len, sip_request_parsed_t *req) {
  const char *method_start = buf;
  const char *p = method_start;
  while (*p && *p != ' ' && (size_t)(p - buf) < len && (size_t)(p - method_start) < sizeof(req->method) - 1) p++;
  size_t method_len = (size_t)(p - method_start);
  if (method_len == 0 || method_len >= sizeof(req->method)) return -1;
  memcpy(req->method, method_start, method_len);
  req->method[method_len] = '\0';
  while (*p == ' ' && (size_t)(p - buf) < len) p++;
  const char *uri_start = p;
  while (*p && *p != ' ' && (size_t)(p - buf) < len && (size_t)(p - uri_start) < sizeof(req->uri) - 1) p++;
  size_t uri_len = (size_t)(p - uri_start);
  if (uri_len == 0 || uri_len >= sizeof(req->uri)) return -1;
  memcpy(req->uri, uri_start, uri_len);
  req->uri[uri_len] = '\0';
  return 0;
}

static int sip_parse_request(const char *buf, size_t len, sip_request_parsed_t *req) {
  memset(req, 0, sizeof(*req));
  req->buf = buf;
  req->len = len;
  req->expires = 3600;
  if (sip_parse_request_line(buf, len, req) != 0) return -1;
  sip_header_copy(buf, len, "Via", req->via, sizeof(req->via));
  sip_header_copy(buf, len, "From", req->from, sizeof(req->from));
  sip_header_copy(buf, len, "To", req->to, sizeof(req->to));
  sip_header_copy(buf, len, "Contact", req->contact, sizeof(req->contact));
  sip_header_copy(buf, len, "Call-ID", req->call_id, sizeof(req->call_id));
  sip_header_copy(buf, len, "CSeq", req->cseq, sizeof(req->cseq));
  const char *exp_val;
  size_t exp_len;
  if (sip_header_get(buf, len, "Expires", &exp_val, &exp_len)) {
    req->expires = atoi(exp_val);
  } else if (sip_header_get(buf, len, "Contact", &exp_val, &exp_len)) {
    const char *semi = memchr(exp_val, ';', exp_len);
    if (semi) {
      const char *exp_p = memmem(exp_val, (size_t)(semi - exp_val), "expires=", 8);
      if (exp_p) req->expires = atoi(exp_p + 8);
    }
  }
  return 0;
}

static void extract_user_from_sip_uri(const char *uri, size_t len, char *user_out, size_t user_size) {
  if (!user_out || user_size == 0 || len == 0) return;
  const char *end = uri + len;
  const char *p = uri;
  while (p < end && *p == ' ') p++;
  if (*p == '"') {
    const char *q = p + 1;
    while (q < end && *q != '"') q++;
    if (q < end) p = q + 1;
  }
  while (p < end && (*p == '<' || *p == ' ' || *p == '\t')) p++;
  if (p + 4 <= end && strncasecmp(p, "sip:", 4) == 0) p += 4;
  const char *user_start = p;
  const char *ats = NULL;
  while (p < end && *p != ';' && *p != ' ' && *p != '\r' && *p != '\n' && *p != '>') {
    if (*p == '@') { ats = p; break; }
    p++;
  }
  if (!ats) return;
  size_t user_len = (size_t)(ats - user_start);
  if (user_len == 0 || user_len >= user_size) return;
  memcpy(user_out, user_start, user_len);
  user_out[user_len] = '\0';
}

static char *handle_register(sip_request_parsed_t *req, size_t *out_len, const struct sockaddr_storage *remote_addr, int tcp_fd) {
  log_trace("handle_register: entry, len=%zu", req->len);
  char user[128] = "";
  char host[128] = "";
  char port[16] = "";
  if (req->to && req->to[0]) {
    extract_user_from_sip_uri(req->to, strlen(req->to), user, sizeof(user));
  }
  if (!user[0] && req->uri && req->uri[0]) {
    sip_request_uri_user(req->uri, strlen(req->uri), user, sizeof(user));
  }
  sip_request_uri_host_port(req->uri, strlen(req->uri), host, sizeof(host), port, sizeof(port));
  log_trace("handle_register: user=%s host=%s to=%s", user, host, req->to);
  char contact_host[128] = "";
  char contact_port[16] = "";
  if (req->contact[0]) {
    const char *c = req->contact;
    if (strncmp(c, "sip:", 4) == 0) c += 4;
    const char *ats = strchr(c, '@');
    if (ats) {
      const char *host_start = ats + 1;
      const char *colon = strchr(host_start, ':');
      size_t hlen = colon ? (size_t)(colon - host_start) : strlen(host_start);
      if (hlen >= sizeof(contact_host)) hlen = sizeof(contact_host) - 1;
      memcpy(contact_host, host_start, hlen);
      contact_host[hlen] = '\0';
      if (colon) {
        size_t plen = strlen(colon + 1);
        if (plen >= sizeof(contact_port)) plen = sizeof(contact_port) - 1;
        memcpy(contact_port, colon + 1, plen);
        contact_port[plen] = '\0';
      }
    }
  }
  char *auth_header = NULL;
  size_t auth_len = 0;
  char *username = NULL;
  char *realm = NULL;
  char *nonce = NULL;
  char *cnonce = NULL;
  char *nc = NULL;
  char *qop = NULL;
  char *uri = NULL;
  char *response = NULL;
  
  if (sip_header_get(req->buf, req->len, "Authorization", (const char**)&auth_header, &auth_len)) {
    log_trace("handle_register: Authorization header found, len=%zu", auth_len);
    sip_parse_authorization_digest(req->buf, req->len, &username, &realm, &nonce, &cnonce, &nc, &qop, &uri, &response);
  } else {
    log_trace("handle_register: NO Authorization header found");
  }
  
  if (!username || !user[0] || strcmp(username, user) != 0) {
    log_trace("handle_register: no valid auth, returning 401");
    char *www_auth = sip_build_www_authenticate("upbx", "nonce123");
    log_trace("handle_register: www_auth=%s", www_auth ? www_auth : "null");
    sip_response_t data = {
      .status_code = 401,
      .reason = "Unauthorized",
      .via = req->via,
      .via = req->via,
      .from = req->from,
      .to = req->to,
      .call_id = req->call_id,
      .cseq = req->cseq,
      .extra_headers = (const char*[]){ www_auth, NULL },
      .n_extra = www_auth ? 1 : 0
    };
    free(username); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(response);
    char *resp = sip_build_response(&data, out_len);
    free(www_auth);
    log_trace("handle_register: 401 response:\n%s", resp ? resp : "null");
    return resp;
  }

  resp_object *ext = config_get_extension(user);
  const char *password = ext ? resp_map_get_string(ext, "secret") : NULL;
  if (!password) {
    log_trace("handle_register: extension %s not found or no password", user);
    free(username); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(response);
    char *www_auth = sip_build_www_authenticate("upbx", "nonce123");
    sip_response_t data = {
      .status_code = 401,
      .reason = "Unauthorized",
      .via = req->via,
      
      .from = req->from,
      .to = req->to,
      .call_id = req->call_id,
      .cseq = req->cseq,
      .extra_headers = (const char*[]){ www_auth, NULL },
      .n_extra = www_auth ? 1 : 0
    };
    char *resp = sip_build_response(&data, out_len);
    free(www_auth);
    return resp;
  }

  HASHHEX ha1, computed_response;
  digest_calc_ha1(NULL, username, realm ? realm : "upbx", password, nonce, cnonce, ha1);
  digest_calc_response(ha1, nonce, nc, cnonce, qop, "REGISTER", uri ? uri : "", NULL, computed_response);

  if (response && strncmp(response, (const char*)computed_response, DIGEST_HASHHEXLEN) != 0) {
    log_trace("handle_register: digest mismatch, expected=%s got=%s", computed_response, response);
    free(username); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(response);
    char *www_auth = sip_build_www_authenticate("upbx", "nonce123");
    sip_response_t data = {
      .status_code = 401,
      .reason = "Unauthorized",
      .via = req->via,
      
      .from = req->from,
      .to = req->to,
      .call_id = req->call_id,
      .cseq = req->cseq,
      .extra_headers = (const char*[]){ www_auth, NULL },
      .n_extra = www_auth ? 1 : 0
    };
    char *resp = sip_build_response(&data, out_len);
    free(www_auth);
    return resp;
  }

  log_trace("handle_register: digest OK, authenticated extension %s", user);
  
  if (req->expires == 0 || req->contact[0] == '\0') {
    registration_remove(user);
  } else {
    registration_add(user, req->contact, (struct sockaddr *)remote_addr, tcp_fd, req->expires);
  }
  
  free(username); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(response);
  
  log_trace("handle_register: building response");
  char contact_uri[512] = "";
  if (req->contact[0]) {
    snprintf(contact_uri, sizeof(contact_uri), "<%s>", req->contact);
  }
  sip_response_t data = {
    .status_code = 200,
    .reason = "OK",
    .via = req->via,
    .from = req->from,
    .to = req->to,
    .call_id = req->call_id,
    .cseq = req->cseq,
    .contact = contact_uri[0] ? contact_uri : NULL
  };
  log_trace("handle_register: calling sip_build_response");
  char *resp = sip_build_response(&data, out_len);
  log_trace("handle_register: sip_build_response returned, len=%zu", out_len ? *out_len : 0);
  return resp;
}

char *sip_process_request(const char *buf, size_t len, size_t *out_len, const struct sockaddr_storage *remote_addr, int tcp_fd) {
  log_trace("sip_process_request: entry");
  sip_request_parsed_t req;
  if (sip_parse_request(buf, len, &req) != 0) {
    log_trace("sip_process_request: parse failed");
    sip_response_t data = { .status_code = 400, .reason = "Bad Request" };
    return sip_build_response(&data, out_len);
  }
  log_trace("sip_process_request: method=%s uri=%s", req.method, req.uri);
  if (strcmp(req.method, "REGISTER") == 0) {
    log_trace("sip_process_request: calling handle_register");
    char *resp = handle_register(&req, out_len, remote_addr, tcp_fd);
    log_trace("sip_process_request: handle_register returned");
    return resp;
  }
  if (strcmp(req.method, "INVITE") == 0) {
    char from_user[128] = "", to_user[128] = "";
    if (req.from && req.from[0]) extract_user_from_sip_uri(req.from, strlen(req.from), from_user, sizeof(from_user));
    if (req.to && req.to[0]) extract_user_from_sip_uri(req.to, strlen(req.to), to_user, sizeof(to_user));

    log_info("INVITE: %s -> %s, call_id=%s", from_user, to_user, req.call_id);

    extension_reg_t *reg = registration_find(from_user);
    if (!reg) {
      log_warn("INVITE: source %s not registered", from_user);
      char *www_auth = sip_build_www_authenticate("upbx", "nonce123");
      sip_response_t data = { 
        .status_code = 401, 
        .reason = "Unauthorized",
        .via = req.via,
        .from = req.from, 
        .to = req.to, 
        .call_id = req.call_id, 
        .cseq = req.cseq,
        .extra_headers = (const char*[]){ www_auth, NULL },
        .n_extra = www_auth ? 1 : 0
      };
      char *resp = sip_build_response(&data, out_len);
      free(www_auth);
      return resp;
    }

    int authorized = 0;
    if (tcp_fd > 0) {
      if (reg->tcp_fd > 0 && reg->tcp_fd == tcp_fd) {
        authorized = 1;
      }
    } else if (remote_addr && remote_addr->ss_family != 0 && reg->remote_addr.ss_family != 0) {
      if (reg->remote_addr.ss_family == remote_addr->ss_family) {
        if (reg->remote_addr.ss_family == AF_INET) {
          struct sockaddr_in *sin = (struct sockaddr_in *)&reg->remote_addr;
          struct sockaddr_in *src = (struct sockaddr_in *)remote_addr;
          if (sin->sin_addr.s_addr == src->sin_addr.s_addr && sin->sin_port == src->sin_port) {
            authorized = 1;
          }
        } else if (reg->remote_addr.ss_family == AF_INET6) {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&reg->remote_addr;
          struct sockaddr_in6 *src = (struct sockaddr_in6 *)remote_addr;
          if (memcmp(&sin6->sin6_addr, &src->sin6_addr, sizeof(sin6->sin6_addr)) == 0 && sin6->sin6_port == src->sin6_port) {
            authorized = 1;
          }
        }
      }
    }
    if (!authorized) {
      log_warn("INVITE: auth failed for %s - registered fd=%d tcp_fd=%d", from_user, reg->tcp_fd, tcp_fd);
      sip_response_t data = { .status_code = 403, .reason = "Forbidden",  .from = req.from, .to = req.to, .call_id = req.call_id, .cseq = req.cseq };
      return sip_build_response(&data, out_len);
    }

    const char *body = NULL;
    size_t body_len = 0;
    sip_request_get_body(req.buf, req.len, &body, &body_len);

    char *new_sdp = NULL;
    int r = call_route_invite(from_user, to_user, req.call_id, body, &new_sdp);
    log_trace("INVITE: call_route returned r=%d new_sdp=%p", r, new_sdp);
    if (r == -2) {
      sip_response_t data = {
        .status_code = 404,
        .reason = "Not Found",
        .via = req.via,
        .from = req.from,
        .to = req.to,
        .call_id = req.call_id,
        .cseq = req.cseq
      };
      return sip_build_response(&data, out_len);
    }
    if (r < 0) {
      sip_response_t data = {
        .status_code = 486,
        .reason = "Busy Here",
        .via = req.via,
        .from = req.from,
        .to = req.to,
        .call_id = req.call_id,
        .cseq = req.cseq
      };
      return sip_build_response(&data, out_len);
    }

    char contact_uri[256] = "";
    char *advertise = config_get_rtp_advertise_addr();
    if (advertise) {
      snprintf(contact_uri, sizeof(contact_uri), "%%3Csip:%%3E; %%3Csip:%s%%3E", advertise);
      free(advertise);
    }

    sip_response_t data = {
      .status_code = 200,
      .reason = "OK",
      
      .from = req.from,
      .to = req.to,
      .call_id = req.call_id,
      .cseq = req.cseq,
      .contact = contact_uri[0] ? contact_uri : NULL,
      .body = new_sdp
    };
    char *resp = sip_build_response(&data, out_len);
    free(new_sdp);
    return resp;
  }

  if (strcmp(req.method, "ACK") == 0 || strcmp(req.method, "BYE") == 0 ||
      strcmp(req.method, "CANCEL") == 0 || strcmp(req.method, "OPTIONS") == 0) {
    if (strcmp(req.method, "BYE") == 0) {
      call_handle_bye(req.call_id);
    }
    sip_response_t data = {
      .status_code = 200,
      .reason = "OK",
      
      .from = req.from,
      .to = req.to,
      .call_id = req.call_id,
      .cseq = req.cseq
    };
    return sip_build_response(&data, out_len);
  }
  sip_response_t data = {
    .status_code = 405,
    .reason = "Method Not Allowed",
    
    .from = req.from,
    .to = req.to,
    .call_id = req.call_id,
    .cseq = req.cseq
  };
  return sip_build_response(&data, out_len);
}
