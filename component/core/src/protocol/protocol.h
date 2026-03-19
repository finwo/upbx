#ifndef UPBX_PROTOCOL_H
#define UPBX_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "call/call.h"
#include "user/user.h"
#include "finwo/mindex.h"

struct upbx_config;

struct upbx_protocol_ctx {
    struct upbx_user_registry *user_reg;
    struct upbx_config *config;
    int *listen_fds;
    struct mindex_t *calls;
    void *conns;
};

struct upbx_protocol_ctx *upbx_protocol_create(void);
void upbx_protocol_free(struct upbx_protocol_ctx *ctx);
void upbx_protocol_start(struct upbx_protocol_ctx *ctx);

#endif
