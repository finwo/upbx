#ifndef UPBX_SIP_PARSE_H
#define UPBX_SIP_PARSE_H

#include <stdbool.h>
#include <stddef.h>

/* Return true if buf[0..len-1] looks like a SIP message (has \r\n\r\n header terminator and min length). */
bool looks_like_sip(const char *buf, size_t len);

/* Siproxd-style raw checks before parsing. Buffer must be \0-terminated. Returns 1 if ok, 0 to reject. */
int sip_security_check_raw(char *sip_buffer, size_t size);

/* Parse status code from first line (SIP/2.0 <code> ...). Returns 0 on parse error. */
int sip_response_status_code(const char *buf, size_t len);

/* Copy reason phrase from first line (after status code) into out, NUL-terminated. out_size > 0. Returns 1 on success. */
int sip_response_reason_phrase(const char *buf, size_t len, char *out, size_t out_size);

/* Find first header with given name (case-insensitive). *value_out points into buf, *value_len_out is length (no NUL). Line folding is merged. Returns 1 if found, 0 otherwise. */
int sip_header_get(const char *buf, size_t len, const char *name, const char **value_out, size_t *value_len_out);

/* Copy first header value into out, NUL-terminated. out_size > 0. Returns 1 if found. */
int sip_header_copy(const char *buf, size_t len, const char *name, char *out, size_t out_size);

/* Parse WWW-Authenticate Digest; set *nonce_out and *realm_out (caller frees). Optional algorithm_out, opaque_out, qop_out (may be NULL). Returns 1 if nonce and realm found. */
int sip_parse_www_authenticate(const char *buf, size_t len, char **nonce_out, char **realm_out,
  char **algorithm_out, char **opaque_out, char **qop_out);

/* Get expires from Contact header (expires= param) or Expires header. Returns seconds or 0 if not found. */
int sip_response_contact_expires(const char *buf, size_t len);

/* --- Request parser and builder (no libosip2) --- */

int sip_is_request(const char *buf, size_t len);
int sip_request_method(const char *buf, size_t len, const char **method_out, size_t *method_len_out);
/* Copy Request-URI from first line (METHOD REQUEST-URI SIP/2.0) into out, NUL-terminated. out_size > 0. Returns 1 on success. */
int sip_request_uri_get(const char *buf, size_t len, char *out, size_t out_size);
int sip_request_uri_user(const char *buf, size_t len, char *user_out, size_t user_size);
int sip_request_uri_host_port(const char *buf, size_t len, char *host_out, size_t host_size, char *port_out, size_t port_size);
int sip_parse_authorization_digest(const char *buf, size_t len,
  char **username_out, char **realm_out, char **nonce_out, char **cnonce_out,
  char **nc_out, char **qop_out, char **uri_out, char **response_out);
int sip_header_uri_user(const char *buf, size_t len, const char *header_name, char *user_out, size_t user_size);

/* Split "host" or "host:port" into host and port. If no ':', port set to "5060". */
int sip_parse_host_port(const char *host_port, char *host_out, size_t host_size, char *port_out, size_t port_size);

/* Format Request-URI into out: sip:user@host[:port] or sip:host[:port]. port omitted if NULL or "5060". out_size > 0. Returns 1 on success. */
int sip_format_request_uri(const char *user, const char *host, const char *port, char *out, size_t out_size);

/* Format header values (no "Contact: " prefix). port omitted if NULL or "5060". */
int sip_wrap_angle_uri(const char *uri, char *out, size_t out_size);
int sip_format_contact_uri_value(const char *user, const char *host, const char *port, char *out, size_t out_size);
int sip_format_from_to_value(const char *display, const char *user, const char *host, const char *port, char *out, size_t out_size);

/* Build full "WWW-Authenticate: Digest ..." line for 401. Caller frees. */
char *sip_build_www_authenticate(const char *realm, const char *nonce);

/* Header value helpers: value before first ';', get param (e.g. tag), append ";tag=value". */
int sip_header_value_before_first_param(const char *buf, size_t len, const char *header_name, char *out, size_t out_size);
int sip_header_get_param(const char *buf, size_t len, const char *header_name, const char *param_name, char *out, size_t out_size);
int sip_append_tag_param(char *out, size_t out_size, const char *tag_value);

/* Build Authorization Digest header value. response_hex = 32-char MD5 hex. algorithm/opaque NULL = omit. */
int sip_build_authorization_digest_value(const char *user, const char *realm, const char *nonce, const char *uri,
  const char *response_hex, const char *algorithm, const char *opaque, char *out, size_t out_size);

/* Build REGISTER request. All args header values. auth_value NULL = no Authorization. Caller frees. */
char *sip_build_register_request(const char *request_uri, const char *via_value, const char *to_val, const char *from_val,
  const char *call_id, const char *cseq, const char *contact_val, int expires, int max_forwards, const char *user_agent,
  const char *auth_value, size_t *out_len);

/* Build response from explicit parts (no copy from request). All args = header values only (no "Via: " prefix). NULL = omit.
 * Via is normalised internally (full "Via: ..." line accepted). extra_headers = "Name: value" lines. Caller frees. */
char *sip_build_response_parts(int status_code, const char *reason,
  const char *via_val, const char *from_val, const char *to_val,
  const char *call_id, const char *cseq_val, const char *contact_val, const char *user_agent,
  const char *body, size_t body_len,
  const char **extra_headers, size_t n_extra, size_t *out_len);

/* Write Via header value only into out (no "Via: " prefix, no CRLF). Same contract as sip_header_copy(..., "Via", ...). */
int sip_make_via_line(const char *host, const char *port, char *out, size_t out_size);

/* Build SIP request from parts. method and request_uri required. Via/From/To/etc = header values only.
 * add_alert_info_for_invite: 1 = when method is INVITE, append Alert-Info (ring) so callee UA shows incoming-call UI. */
char *sip_build_request_parts(const char *method, const char *request_uri,
  const char *via_val, const char *from_val, const char *to_val,
  const char *call_id, const char *cseq_val, const char *contact_val,
  int add_alert_info_for_invite,
  const char *body, size_t body_len, size_t *out_len);

int sip_request_get_body(const char *buf, size_t len, const char **body_out, size_t *body_len_out);

/* ---- Packet rewrite helpers ----
 * Each copies buf[0..len-1] to out[0..out_cap-1] with one modification.
 * Returns new length, or -1 on error. Composable: chain output → input. */

/* Replace Request-URI in first line (METHOD <old> SIP/2.0 → METHOD <new_uri> SIP/2.0). */
int sip_rewrite_request_uri(const char *buf, size_t len, const char *new_uri, char *out, size_t out_cap);

/* Insert "Via: <via_value>\r\n" after the first line. */
int sip_prepend_via(const char *buf, size_t len, const char *via_value, char *out, size_t out_cap);

/* Remove the first Via header line. */
int sip_strip_top_via(const char *buf, size_t len, char *out, size_t out_cap);

/* Replace the value of the first occurrence of header_name (case-insensitive).
 * E.g. sip_rewrite_header(buf, len, "Contact", "<sip:x@y>", out, cap). */
int sip_rewrite_header(const char *buf, size_t len, const char *header_name,
                       const char *new_value, char *out, size_t out_cap);

/* Insert a new header line before the header/body separator.
 * If header_name already exists, does nothing (copies verbatim). */
int sip_insert_header(const char *buf, size_t len, const char *header_name,
                      const char *value, char *out, size_t out_cap);

/* Replace the message body and update Content-Length (and Content-Type if body present).
 * new_body==NULL or new_body_len==0 removes the body. */
int sip_rewrite_body(const char *buf, size_t len,
                     const char *new_body, size_t new_body_len,
                     char *out, size_t out_cap);

#endif
