#ifndef UPBX_INFRASTRUCTURE_UDPHOLE_H
#define UPBX_INFRASTRUCTURE_UDPHOLE_H

#include "domain/pbx/sip/udphole_client.h"

udphole_client_t *infrastructure_udphole_create(const char *address, const char *auth_user, const char *auth_pass);
void              infrastructure_udphole_destroy(udphole_client_t *client);

int  infrastructure_udphole_init_global(void);
void infrastructure_udphole_cleanup_global(void);

#endif
