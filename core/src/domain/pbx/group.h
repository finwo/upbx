#ifndef UPBX_PBX_GROUP_H
#define UPBX_PBX_GROUP_H

#include <stdbool.h>

const char *group_find_for_extension(const char *extension);

bool group_get_allow_incoming_cross_group(const char *group_prefix);

bool group_get_allow_outgoing_cross_group(const char *group_prefix);

void group_config_init(void);

void group_config_free(void);

#endif
