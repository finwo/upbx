#ifndef UDPHOLE_CONFIG_H
#define UDPHOLE_CONFIG_H

#include "common/resp.h"

extern resp_object *global_cfg;
extern resp_object *pending_cfg;

void config_init(void);
int config_load(resp_object *cfg, const char *path);
int config_reload(void);
void config_set_path(const char *path);
const char *config_get_path(void);

#endif