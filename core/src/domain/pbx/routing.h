#ifndef UPBX_PBX_ROUTING_H
#define UPBX_PBX_ROUTING_H

#include "domain/pbx/registration.h"

pbx_registration_t *pbx_route(const char *source_extension, const char *dialed_number, const char *source_group_prefix);

#endif
