#ifndef UPBX_SIP_PARSE_H
#define UPBX_SIP_PARSE_H

#include <stddef.h>

/* Siproxd-style raw checks before parsing. Buffer must be \0-terminated. Returns 1 if ok, 0 to reject. */
int sip_security_check_raw(char *sip_buffer, size_t size);

/* In-place fixup: Asterisk Alert-Info removal, tag=<null>->tag=0, trim trailing blank line, ensure last header ends with CRLF. *len and buf_size in bytes. */
void sip_fixup_for_parse(char *buf, size_t *len, size_t buf_size);

/* Minimal SIP response parser (no libosip2). Buffer is the raw response (e.g. "SIP/2.0 401 Unauthorized\r\n..."). */

/* Parse status code from first line (SIP/2.0 <code> ...). Returns 0 on parse error. */
int sip_response_status_code(const char *buf, size_t len);

/* Find first header with given name (case-insensitive). *value_out points into buf, *value_len_out is length (no NUL). Line folding is merged. Returns 1 if found, 0 otherwise. */
int sip_header_get(const char *buf, size_t len, const char *name, const char **value_out, size_t *value_len_out);

/* Parse WWW-Authenticate Digest; set *nonce_out and *realm_out (caller frees). Returns 1 if both found. */
int sip_parse_www_authenticate(const char *buf, size_t len, char **nonce_out, char **realm_out);

/* Get expires from Contact header (expires= param) or Expires header. Returns seconds or 0 if not found. */
int sip_response_contact_expires(const char *buf, size_t len);

/* --- Request parser and builder (no libosip2) --- */

int sip_is_request(const char *buf, size_t len);
int sip_request_method(const char *buf, size_t len, const char **method_out, size_t *method_len_out);
int sip_request_uri_user(const char *buf, size_t len, char *user_out, size_t user_size);
int sip_request_uri_host_port(const char *buf, size_t len, char *host_out, size_t host_size, char *port_out, size_t port_size);
int sip_parse_authorization_digest(const char *buf, size_t len,
  char **username_out, char **realm_out, char **nonce_out, char **cnonce_out,
  char **nc_out, char **qop_out, char **uri_out, char **response_out);
int sip_header_uri_user(const char *buf, size_t len, const char *header_name, char *user_out, size_t user_size);

/* Build response from request; extra_headers is array of "Name: value" strings. Caller frees. If out_len non-NULL, set to length. */
char *sip_build_response(const char *request_buf, size_t request_len, int status_code, const char *reason_phrase,
  int copy_contact, const char **extra_headers, size_t n_extra, size_t *out_len);

int sip_request_get_body(const char *buf, size_t len, const char **body_out, size_t *body_len_out);
char *sip_request_replace_uri(const char *buf, size_t len, const char *user, const char *host, const char *port);
char *sip_request_add_via(const char *buf, size_t len, const char *host, const char *port);
char *sip_request_replace_body(const char *buf, size_t len, const char *new_body, size_t new_body_len);
char *sip_response_strip_first_via(const char *buf, size_t len);

#endif
