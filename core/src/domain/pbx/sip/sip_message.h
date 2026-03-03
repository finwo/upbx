#ifndef UPBX_PBX_SIP_MESSAGE_H
#define UPBX_PBX_SIP_MESSAGE_H

#include <stddef.h>

typedef struct {
  const char *name;
  size_t      name_len;
  const char *value;
  size_t      value_len;
} sip_header_t;

typedef struct {
  const char   *data;
  size_t        len;
  const char   *method;
  size_t        method_len;
  const char   *uri;
  size_t        uri_len;
  int           status_code;
  const char   *reason;
  size_t        reason_len;
  sip_header_t *headers;
  size_t        header_count;
  const char   *body;
  size_t        body_len;
} sip_message_t;

int sip_message_parse(const char *buf, size_t len, sip_message_t *out);

const char *sip_message_header_get(const sip_message_t *msg, const char *name, size_t *value_len);

int sip_message_header_get_all(const sip_message_t *msg, const char *name, const char **values, size_t *value_lens,
                               size_t max_count, size_t *out_count);

int sip_message_header_copy(const sip_message_t *msg, const char *name, char *out, size_t out_size);

void sip_message_free(sip_message_t *msg);

int sip_is_request(const sip_message_t *msg);

int sip_uri_extract_user(const char *uri, size_t uri_len, char *out, size_t out_size);

int sip_header_uri_extract_user(const sip_message_t *msg, const char *header_name, char *out, size_t out_size);

int sip_uri_extract_host_port(const char *uri, size_t uri_len, char *host_out, size_t host_size, char *port_out,
                              size_t port_size);

#endif
