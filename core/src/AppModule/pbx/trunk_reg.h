#ifndef UPBX_PBX_TRUNK_REG_H
#define UPBX_PBX_TRUNK_REG_H

#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "SchedulerModule/protothreads.h"
#include "SchedulerModule/scheduler.h"

#define TRUNK_REG_MAX_TRUNKS 64
#define TRUNK_REG_DEFAULT_EXPIRY 300000
#define TRUNK_REG_REFRESH_BEFORE 15000
#define TRUNK_REG_RETRY_INTERVAL 5000

typedef struct trunk_reg {
    char *name;
    char *address;
    char *host;
    int port;
    char *username;
    char *password;
    char *did;

    int fd;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addr_len;
    struct pt pt;

    int64_t expires_at;
    int64_t retry_at;
    uint32_t cseq;
    char call_id[64];
    char branch[64];

    bool refresh_requested;

    char recv_buf[4096];
    struct sockaddr_storage from_addr;
    socklen_t from_len;
    ssize_t recv_len;

    int *ready_fds;
} trunk_reg_t;

void trunk_reg_start_all(void);
void trunk_reg_stop_all(void);

trunk_reg_t *trunk_reg_find(const char *name);
trunk_reg_t **trunk_reg_list(size_t *count);

void trunk_reg_refresh(const char *name);

bool trunk_reg_is_registered(const char *name);
time_t trunk_reg_get_expires_at(const char *name);

#endif
