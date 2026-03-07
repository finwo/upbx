#ifndef UPBX_PBX_SIP_HANDLER_H
#define UPBX_PBX_SIP_HANDLER_H

#include <stddef.h>
#include <sys/socket.h>

#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sip_message.h"

char *sip_handle_register(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
);

#endif
