#ifndef UPBX_PBX_REGISTRATION_H
#define UPBX_PBX_REGISTRATION_H

#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "domain/protothreads.h"
#include "domain/scheduler.h"

typedef struct {
    char *number;
    char *contact;
    struct sockaddr_storage remote_addr;
    time_t expires_at;
    time_t registered_at;
} registration_t;

void registration_init(void);

void registration_set_dir(const char *path);

const char *registration_get_dir(void);

registration_t *registration_find(const char *number);

int registration_add(const char *number, const char *contact,
                     const struct sockaddr *remote_addr, int expires_seconds);

void registration_remove(const char *number);

void registration_free(registration_t *reg);

PT_THREAD(registration_cleanup_pt(struct pt *pt, int64_t timestamp, struct pt_task *task));

#endif
