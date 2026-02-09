/*
 * SIP parse helpers: security_check_raw, in-place fixup, and minimal response parser (no libosip2).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#define SEC_MINLEN      16
#define SEC_MAXLINELEN  2048

/* Siproxd security_check_raw: same checks before osip_message_parse. */
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
    if (strncmp(sip_buffer, "INVITE  SIP/2.0",  15) == 0) return 0;
    if (strncmp(sip_buffer, "ACK  SIP/2.0",     12) == 0) return 0;
    if (strncmp(sip_buffer, "BYE  SIP/2.0",     12) == 0) return 0;
    if (strncmp(sip_buffer, "CANCEL  SIP/2.0",  15) == 0) return 0;
    if (strncmp(sip_buffer, "REGISTER  SIP/2.0", 17) == 0) return 0;
    if (strncmp(sip_buffer, "OPTIONS  SIP/2.0",  16) == 0) return 0;
    if (strncmp(sip_buffer, "INFO  SIP/2.0",     13) == 0) return 0;
  }

  return 1;
}

/* Single in-place fixup so osip_message_parse does not crash. Does: drop header lines with no ':',
 * Asterisk Alert-Info removal, tag=<null> -> tag=0, trim trailing blank line, ensure last header ends with CRLF. */
void sip_fixup_for_parse(char *buf, size_t *len, size_t buf_size) {
  size_t o = *len;
  size_t j;
  size_t i;
  char *p;
  char *eol;
  size_t tail_len;
  size_t line_start, line_end, line_content_len;
  int has_colon;

  /* Unfold SIP continuation lines (\r\n followed by space/tab): merge into previous line so libosip2 never sees a line with no colon (-> hname=NULL -> strcmp crash). */
  for (j = 0; j + 2 < o; j++) {
    if (buf[j] == '\r' && buf[j + 1] == '\n' && (buf[j + 2] == ' ' || buf[j + 2] == '\t')) {
      memmove(buf + j, buf + j + 2, o - (j + 2));
      o -= 2;
      j--; /* re-check this position (could be another LWS) */
    }
  }

  /* Drop any header line (after the status line) that still has no ':' (defensive). */
  p = (char *)memchr(buf, '\n', o);
  i = p ? (size_t)(p + 1 - buf) : o; /* skip status line */
  while (i < o) {
    p = (char *)memchr(buf + i, '\n', o - i);
    if (!p) break;
    line_end = (size_t)(p + 1 - buf);
    line_content_len = (size_t)(p - buf) - i;
    if (p > buf && p[-1] == '\r' && line_content_len > 0) line_content_len--;
    if (line_content_len == 0) break; /* blank line = end of headers */
    has_colon = 0;
    for (j = i; j < i + line_content_len; j++) {
      if (buf[j] == ':') { has_colon = 1; break; }
    }
    if (!has_colon) {
      line_start = i;
      tail_len = o - line_end;
      memmove(buf + line_start, buf + line_end, tail_len);
      o -= (line_end - line_start);
      continue;
    }
    i = line_end;
  }

  /* Siproxd sip_fixup_asterisk: remove malformed Alert-Info when User-Agent is Asterisk PBX. */
  if (strstr(buf, "\r\nUser-Agent: Asterisk PBX\r\n")) {
    p = strstr(buf, "\r\nAlert-Info: ");
    if (p && (eol = strstr(p + 2, "\r\n")) != NULL) {
      tail_len = (size_t)(buf + o - eol);
      memmove(p, eol, tail_len);
      o = (size_t)(p - buf) + tail_len;
    }
  }

  /* tag=<null> -> tag=0; avoid unbalanced brackets and null in parser */
  for (j = 0; j + 10 <= o; ) {
    if (memcmp(buf + j, "tag=<null>", 10) == 0) {
      memcpy(buf + j, "tag=0", 5);
      memmove(buf + j + 5, buf + j + 10, o - (j + 10));
      o -= 5;
      j += 5;
    } else {
      j++;
    }
  }

  /* Trim trailing blank line so parser does not see empty line (null name -> strcmp crash). */
  if (o >= 4 && buf[o - 4] == '\r' && buf[o - 3] == '\n' && buf[o - 2] == '\r' && buf[o - 1] == '\n')
    o -= 2;

  /* Ensure last header ends with CRLF so osip does not parse an empty "next" line. */
  if (o > 0 && buf[o - 1] != '\n' && o + 2 < buf_size) {
    buf[o] = '\r';
    buf[o + 1] = '\n';
    buf[o + 2] = '\0';
    o += 2;
  } else {
    buf[o] = '\0';
  }
  *len = o;
}

/* --- Minimal SIP response parser --- */

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
      /* merge continuation lines */
      if (p + 2 < end && p[0] == '\r' && p[1] == '\n' && (p[2] == ' ' || p[2] == '\t')) {
        p += 2;
        while (p < end && *p != '\r' && *p != '\n') p++;
        *value_len_out = (size_t)(p - (*value_out));
      }
      return 1;
    }
    if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
    else if (p < end) p += 1;
  }
  return 0;
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

/* --- Request parser (no libosip2) --- */

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
  char *u = NULL, *r = NULL, *n = NULL, *uri = NULL, *resp = NULL;
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
  if (!parse_digest_param(val, val_len, "username", username_out ? username_out : &u)) return 0;
  if (!parse_digest_param(val, val_len, "realm", realm_out ? realm_out : &r)) {
    if (username_out) free(*username_out); else free(u);
    if (username_out) *username_out = NULL;
    if (realm_out) free(*realm_out); else free(r);
    if (realm_out) *realm_out = NULL;
    return 0;
  }
  if (!parse_digest_param(val, val_len, "nonce", nonce_out ? nonce_out : &n)) {
    if (username_out) free(*username_out); else free(u);
    if (realm_out) free(*realm_out); else free(r);
    if (username_out) *username_out = NULL;
    if (realm_out) *realm_out = NULL;
    return 0;
  }
  if (!parse_digest_param(val, val_len, "uri", uri_out ? uri_out : &uri)) {
    if (username_out) free(*username_out); else free(u);
    if (realm_out) free(*realm_out); else free(r);
    if (nonce_out) free(*nonce_out); else free(n);
    if (username_out) *username_out = NULL;
    if (realm_out) *realm_out = NULL;
    if (nonce_out) *nonce_out = NULL;
    return 0;
  }
  if (!parse_digest_param(val, val_len, "response", response_out ? response_out : &resp)) {
    if (username_out) free(*username_out); else free(u);
    if (realm_out) free(*realm_out); else free(r);
    if (nonce_out) free(*nonce_out); else free(n);
    if (uri_out) free(*uri_out); else free(uri);
    if (username_out) *username_out = NULL;
    if (realm_out) *realm_out = NULL;
    if (nonce_out) *nonce_out = NULL;
    if (uri_out) *uri_out = NULL;
    return 0;
  }
  if (!username_out) free(u);
  if (!realm_out) free(r);
  if (!nonce_out) free(n);
  if (!uri_out) free(uri);
  if (!response_out) free(resp);
  if (cnonce_out) parse_digest_param(val, val_len, "cnonce", cnonce_out);
  if (nc_out) parse_digest_param(val, val_len, "nc", nc_out);
  if (qop_out) parse_digest_param(val, val_len, "qop", qop_out);
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

/* Append all header lines whose name matches (case-insensitive) from request to dest. */
static size_t append_header_lines(const char *req, size_t req_len, const char *name, size_t name_len,
    char *dest, size_t dest_used, size_t dest_size) {
  const char *p = req;
  const char *end = req + req_len;
  while (p < end && *p != '\r' && *p != '\n') p++;
  if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2; else if (p < end) p++;
  while (p < end) {
    const char *line_start = p;
    while (p < end && *p != '\r' && *p != '\n') p++;
    if (line_start == p) break;
    size_t line_len = (size_t)(p - line_start);
    if (line_len >= name_len + 1 && line_start[name_len] == ':' &&
        header_name_match(line_start, line_len, name)) {
      size_t need = line_len + 2;
      if (dest_used + need > dest_size) break;
      memcpy(dest + dest_used, line_start, line_len);
      dest[dest_used + line_len] = '\r';
      dest[dest_used + line_len + 1] = '\n';
      dest_used += need;
    }
    if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2; else if (p < end) p++;
  }
  return dest_used;
}

/* Build SIP response from request. Copies Via, From, To, Call-ID, CSeq; optionally Contact.
 * extra_headers is array of "Name: value" strings (or NULL if n_extra==0). Caller frees returned buffer.
 * If out_len is not NULL, set to response length (excluding trailing NUL). */
char *sip_build_response(const char *request_buf, size_t request_len, int status_code, const char *reason_phrase,
    int copy_contact, const char **extra_headers, size_t n_extra, size_t *out_len) {
  size_t cap = 256 + request_len + 1024;
  char *out = malloc(cap);
  if (!out) return NULL;
  size_t used = 0;
  int n = snprintf(out + used, cap - used, "SIP/2.0 %d %s\r\n", status_code, reason_phrase ? reason_phrase : "OK");
  if (n < 0 || (size_t)n >= cap - used) { free(out); return NULL; }
  used += (size_t)n;

  static const char *headers[] = { "Via", "From", "To", "Call-ID", "CSeq" };
  for (size_t h = 0; h < sizeof(headers)/sizeof(headers[0]); h++) {
    const char *name = headers[h];
    size_t nlen = strlen(name);
    used = append_header_lines(request_buf, request_len, name, nlen, out, used, cap);
  }
  if (copy_contact)
    used = append_header_lines(request_buf, request_len, "Contact", 7, out, used, cap);
  for (size_t i = 0; i < n_extra && extra_headers[i]; i++) {
    size_t len = strlen(extra_headers[i]);
    if (used + len + 2 > cap) break;
    memcpy(out + used, extra_headers[i], len);
    used += len;
    out[used++] = '\r';
    out[used++] = '\n';
  }
  if (used + 2 > cap) { free(out); return NULL; }
  out[used++] = '\r';
  out[used++] = '\n';
  { char *ret = realloc(out, used + 1); if (ret) { ret[used] = '\0'; if (out_len) *out_len = used; return ret; } if (out_len) *out_len = used; return out; }
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

/* Clone request buffer and replace Request-URI line with sip:user@host:port. Caller frees. */
char *sip_request_replace_uri(const char *buf, size_t len, const char *user, const char *host, const char *port) {
  const char *end = buf + len;
  const char *first_end = buf;
  while (first_end < end && *first_end != '\r' && *first_end != '\n') first_end++;
  const char *space1 = buf;
  while (space1 < first_end && *space1 != ' ') space1++;
  if (space1 >= first_end) return NULL;
  const char *uri_start = space1 + 1;
  const char *space2 = uri_start;
  while (space2 < first_end && *space2 != ' ') space2++;
  if (space2 >= first_end) return NULL;
  size_t method_len = (size_t)(space1 - buf);
  size_t tail_len = (size_t)(first_end - space2);
  size_t new_uri_len = 4 + (user ? strlen(user) : 0) + 1 + (host ? strlen(host) : 0) + (port && port[0] ? 1 + strlen(port) : 0);
  char *new_uri = malloc(new_uri_len + 1);
  if (!new_uri) return NULL;
  char *q = new_uri;
  memcpy(q, "sip:", 4); q += 4;
  if (user) { size_t u = strlen(user); memcpy(q, user, u); q += u; }
  *q++ = '@';
  if (host) { size_t h = strlen(host); memcpy(q, host, h); q += h; }
  if (port && port[0]) { *q++ = ':'; size_t pn = strlen(port); memcpy(q, port, pn); q += pn; }
  *q = '\0';
  size_t rest = (size_t)(end - first_end);
  size_t new_len = method_len + 1 + new_uri_len + tail_len + rest;
  char *out = malloc(new_len + 1);
  if (!out) { free(new_uri); return NULL; }
  char *o = out;
  memcpy(o, buf, method_len); o += method_len;
  *o++ = ' ';
  memcpy(o, new_uri, new_uri_len); o += new_uri_len;
  memcpy(o, space2, tail_len + rest);
  out[new_len] = '\0';
  free(new_uri);
  return out;
}

/* Prepend Via line to request. Caller frees. */
char *sip_request_add_via(const char *buf, size_t len, const char *host, const char *port) {
  char via[256];
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int n = snprintf(via, sizeof(via), "Via: SIP/2.0/UDP %s:%s;rport;branch=z9hG4bK%lx%lx%x\r\n",
    host, port, (long)ts.tv_sec, (long)ts.tv_nsec, (unsigned)rand());
  if (n < 0 || n >= (int)sizeof(via)) return NULL;
  size_t via_len = (size_t)n;
  size_t first_line = 0;
  while (first_line < len && buf[first_line] != '\r' && buf[first_line] != '\n') first_line++;
  size_t rest = len - first_line;
  char *out = malloc(first_line + via_len + rest + 1);
  if (!out) return NULL;
  memcpy(out, buf, first_line);
  memcpy(out + first_line, via, via_len);
  memcpy(out + first_line + via_len, buf + first_line, rest);
  out[first_line + via_len + rest] = '\0';
  return out;
}

/* Replace body in request (from \r\n\r\n). new_body may be NULL (removes body). Caller frees. */
char *sip_request_replace_body(const char *buf, size_t len, const char *new_body, size_t new_body_len) {
  const char *body_start = NULL;
  size_t body_len = 0;
  if (!sip_request_get_body(buf, len, &body_start, &body_len)) {
    if (!new_body || new_body_len == 0) {
      char *copy = malloc(len + 1);
      if (!copy) return NULL;
      memcpy(copy, buf, len);
      copy[len] = '\0';
      return copy;
    }
    size_t need = len + 2 + new_body_len + 1;
    char *out = malloc(need);
    if (!out) return NULL;
    memcpy(out, buf, len);
    out[len] = '\r'; out[len+1] = '\n'; out[len+2] = '\r'; out[len+3] = '\n';
    memcpy(out + len + 4, new_body, new_body_len);
    out[len + 4 + new_body_len] = '\0';
    return out;
  }
  size_t header_len = (size_t)(body_start - buf);
  size_t new_total = header_len + (new_body ? new_body_len : 0);
  char *out = malloc(new_total + 1);
  if (!out) return NULL;
  memcpy(out, buf, header_len);
  if (new_body && new_body_len) memcpy(out + header_len, new_body, new_body_len);
  out[new_total] = '\0';
  /* Update Content-Length header to match new body length (in-place only if new line fits) */
  {
    const char *cl = "Content-Length: ";
    size_t cl_len = 16;
    char *h = out;
    while (h + cl_len <= out + header_len) {
      if (strncasecmp(h, cl, cl_len) == 0) {
        char *line_end = h;
        while (line_end < out + header_len && *line_end != '\r' && *line_end != '\n') line_end++;
        size_t line_len = (size_t)(line_end - h);
        size_t after = (size_t)(out + header_len - line_end);
        char new_line[32];
        int n = snprintf(new_line, sizeof(new_line), "Content-Length: %zu", new_body ? new_body_len : 0);
        if (n > 0 && (size_t)n <= line_len) {
          memcpy(h, new_line, (size_t)n);
          if ((size_t)n < line_len)
            memmove(h + n, line_end, after);
        }
        break;
      }
      while (h < out + header_len && *h != '\r' && *h != '\n') h++;
      if (h + 1 < out + header_len && h[0] == '\r' && h[1] == '\n') h += 2; else if (h < out + header_len) h++;
    }
  }
  return out;
}

/* Response: strip first Via line. Caller frees. */
char *sip_response_strip_first_via(const char *buf, size_t len) {
  const char *p = buf;
  const char *end = buf + len;
  while (p < end && *p != '\r' && *p != '\n') p++;
  if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2; else if (p < end) p++;
  if (p + 4 >= end || strncasecmp(p, "Via:", 4) != 0) {
    char *copy = malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, buf, len);
    copy[len] = '\0';
    return copy;
  }
  const char *via_start = p;
  while (p < end && *p != '\r' && *p != '\n') p++;
  size_t skip = (size_t)(p - via_start);
  if (p + 1 < end && p[0] == '\r' && p[1] == '\n') skip += 2; else if (p < end) skip += 1;
  size_t new_len = len - skip;
  char *out = malloc(new_len + 1);
  if (!out) return NULL;
  memcpy(out, buf, (size_t)(via_start - buf));
  memcpy(out + (size_t)(via_start - buf), via_start + skip, (size_t)(end - (via_start + skip)));
  out[new_len] = '\0';
  return out;
}
