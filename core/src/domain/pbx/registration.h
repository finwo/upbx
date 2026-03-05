#ifndef UPBX_PBX_REGISTRATION_H
#define UPBX_PBX_REGISTRATION_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include "common/scheduler.h"

typedef struct {
  char                   *number;
  char                   *contact;
  char                   *group;
  struct sockaddr_storage remote_addr;
  time_t                  expires_at;
  time_t                  registered_at;
} registration_t;

void registration_init(void);

void registration_set_dir(const char *path);

const char *registration_get_dir(void);

registration_t *registration_find(const char *number);

registration_t *registration_find_by_addr(const struct sockaddr *remote_addr);

int registration_is_pattern(const char *extension);

int registration_match_pattern(const char *pattern, const char *extension);

int pattern_specificity_cmp(const char *a, const char *b);

const char *registration_pattern_best_match(const char *extension);

int registration_add(const char *number, const char *contact, const char *group, const struct sockaddr *remote_addr, int expires_seconds);

void registration_remove(const char *number);

void registration_free(registration_t *reg);

int registration_cleanup_pt(int64_t timestamp, struct pt_task *task);

#endif
