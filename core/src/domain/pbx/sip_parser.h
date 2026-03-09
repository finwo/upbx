#ifndef UPBX_PBX_SIP_PARSER_H
#define UPBX_PBX_SIP_PARSER_H

#include <stddef.h>

typedef struct {
  char *method;
  char *uri;
  char *via;
  char *from;
  char *to;
  char *call_id;
  char *contact;
  int cseq;
  char *cseq_method;
  char *from_tag;
  char *to_tag;
  int content_length;
  char *authorization;
  char *www_authenticate;
  char *content_type;
  char *body;
  char *raw_request_line;
} sip_message_t;

void sip_message_free(sip_message_t *msg);
sip_message_t *sip_parse(const char *buf, size_t len);

int sip_is_request(const sip_message_t *msg);
int sip_response_status_code(const sip_message_t *msg);
const char *sip_header_get(const sip_message_t *msg, const char *name);

char *sip_request_uri_user(const sip_message_t *msg);
char *sip_request_uri_user_from_to(const sip_message_t *msg);
char *sip_request_uri_host_port(const sip_message_t *msg);
char *sip_format_request_uri(const char *user, const char *host_port);

void sip_rewrite_request_uri(sip_message_t *msg, const char *new_uri);
void sip_prepend_via(sip_message_t *msg, const char *via);
void sip_replace_via(sip_message_t *msg, const char *via);
void sip_strip_top_via(sip_message_t *msg);
void sip_update_to_tag(sip_message_t *msg, const char *tag);

int sip_security_check_raw(const char *auth_header, const char *method, const char *uri, const char *password);

#endif
