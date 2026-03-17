#ifndef UPBX_DOMAIN_CONFIG_H
#define UPBX_DOMAIN_CONFIG_H

#include "common/resp.h"

extern resp_object *domain_cfg;

void domain_config_init(void);
void domain_config_free(void);

#endif
