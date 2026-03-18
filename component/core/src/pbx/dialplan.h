#ifndef PBX_DIALPLAN_H
#define PBX_DIALPLAN_H

#include <stdbool.h>

#include "config/config.h"

struct dialplan_result {
  char *target;
  int is_trunk;
  int is_emergency;
};

int dialplan_match_extension(const char *dialed_number, const char *group_prefix, struct upbx_extension **matches, size_t *match_count);

int dialplan_route(struct upbx_config *config, const char *caller_group, const char *dialed_number, struct dialplan_result *result);

int dialplan_is_emergency(struct upbx_config *config, const char *number);

#endif // PBX_DIALPLAN_H
