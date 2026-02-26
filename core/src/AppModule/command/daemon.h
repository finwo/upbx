#ifndef __APPMODULE_DAEMON_H__
#define __APPMODULE_DAEMON_H__

#include <sys/select.h>
#include <stdint.h>
#include "common/pt.h"

struct pt_task;

typedef char (*pt_task_fn)(struct pt *pt, int64_t timestamp, struct pt_task *task);

typedef struct pt_task {
  struct pt pt;
  void *udata;
  pt_task_fn func;
  int *read_fds;
  int read_fds_count;
  int maxfd;
  char is_active;
} pt_task_t;

int pt_task_has_data(pt_task_t *task, int *out_fd);
pt_task_t *appmodule_pt_add(pt_task_fn func, void *udata);
void appmodule_pt_stop(void);
int appmodule_cmd_daemon(int argc, const char **argv);

#endif
