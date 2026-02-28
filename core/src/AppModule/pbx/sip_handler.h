#ifndef UPBX_PBX_SIP_HANDLER_H
#define UPBX_PBX_SIP_HANDLER_H

#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "AppModule/sip/sip_message.h"

char *sip_handle_register(sip_message_t *msg,
                           const struct sockaddr_storage *remote_addr,
                           size_t *response_len);

#endif
