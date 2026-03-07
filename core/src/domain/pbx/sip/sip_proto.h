#ifndef UPBX_PBX_SIP_PROTO_H
#define UPBX_PBX_SIP_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sip_message.h"

typedef char *(*sip_method_handler)(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
);

char *sip_proto_build_response(
  const sip_message_t *req,
  int status_code,
  const char *reason,
  const char *extra_headers,
  const char *body,
  size_t body_len,
  size_t *out_len,
  const char *via_override
);

char *sip_proto_build_request(
  const char *method,
  const char *uri,
  const char *via_host,
  const char *from_header,
  const char *to_header,
  const char *call_id,
  const char *cseq,
  const char *contact,
  const char *content_type,
  const char *body,
  size_t body_len,
  size_t *out_len,
  const char *branch
);

#endif
