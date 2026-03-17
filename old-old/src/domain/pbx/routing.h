#ifndef UPBX_PBX_ROUTING_H
#define UPBX_PBX_ROUTING_H

#include "domain/pbx/registration.h"

pbx_registration_t *pbx_route(const char *source_extension, const char *dialed_number, const char *source_group_prefix);

/* Check if dialed_number is in the global emergency number list.
 * Returns 1 if it is an emergency number, 0 otherwise. */
int pbx_is_emergency(const char *dialed_number);

#endif
