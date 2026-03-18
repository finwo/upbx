#ifndef SIP_PARSER_H
#define SIP_PARSER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

enum sip_method {
  SIP_METHOD_UNKNOWN,
  SIP_METHOD_INVITE,
  SIP_METHOD_ACK,
  SIP_METHOD_BYE,
  SIP_METHOD_CANCEL,
  SIP_METHOD_OPTIONS,
  SIP_METHOD_REGISTER,
  SIP_METHOD_PRACK,
  SIP_METHOD_NOTIFY,
  SIP_METHOD_SUBSCRIBE,
  SIP_METHOD_INFO,
  SIP_METHOD_REFER,
  SIP_METHOD_MESSAGE,
};

struct sip_request {
  enum sip_method method;
  char *method_str;
  char *uri;
  char *version;

  char *from;
  char *to;
  char *call_id;
  char *cseq;
  char *contact;
  char *via;
  char *branch;
  char *user_agent;
  char *content_type;
  int content_length;
  int expires;

  char *authorization;
  char *proxy_authorization;

  char *body;
  size_t body_len;
};

struct sip_response {
  int status_code;
  char *reason_phrase;
  char *version;

  char *via;
  char *from;
  char *to;
  char *call_id;
  char *cseq;

  char *content_type;
  int content_length;

  char *body;
  size_t body_len;
};

void sip_request_free(struct sip_request *req);
void sip_response_free(struct sip_response *resp);

struct sip_request *sip_parse_request(const char *data, size_t len);
struct sip_response *sip_parse_response(const char *data, size_t len);

enum sip_method sip_method_from_string(const char *str);
const char *sip_method_to_string(enum sip_method method);

#endif // SIP_PARSER_H
