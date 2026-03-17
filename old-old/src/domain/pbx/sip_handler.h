#ifndef UPBX_PBX_SIP_HANDLER_H
#define UPBX_PBX_SIP_HANDLER_H

#include <sys/socket.h>

#include "domain/pbx/registration.h"
#include "domain/pbx/sip_parser.h"

typedef struct {
  int                     fd;
  struct sockaddr_storage remote_addr;
  sip_message_t          *msg;
  pbx_registration_t     *reg;
} pbx_sip_context_t;

void pbx_sip_handle(pbx_sip_context_t *ctx);

/* Rewrite SDP for media proxy: replace c=, o= addresses and m= ports.
 * Used by both ext-to-ext and trunk call paths. */
char *pbx_rewrite_sdp_for_proxy(const char *sdp, const char *advertise_ip, int *ports, int port_count, int *rtcp_ports,
                                int rtcp_port_count);

#endif
