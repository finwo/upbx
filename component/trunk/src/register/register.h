#ifndef TRK_REGISTER_H
#define TRK_REGISTER_H

#include "config/config.h"
#include "finwo/scheduler.h"

struct trunk_state;

struct register_state {
    struct trk_config *config;
    struct trunk_state *trunk;
    int fd;
    int registered;
    int64_t last_register;
    int expires;
    pt_task_t *task;
};

struct register_state *register_create(struct trk_config *cfg, struct trunk_state *trunk, int fd);
void register_free(struct register_state *rs);

void register_on_401(struct register_state *rs, const char *www_auth);
void register_on_200(struct register_state *rs, int expires);

#endif
