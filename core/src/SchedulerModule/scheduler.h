#ifndef __SCHEDULERMODULE_SCHEDULER_H__
#define __SCHEDULERMODULE_SCHEDULER_H__

#include "protothreads.h"

#include <stdint.h>
#include <sys/select.h>

struct pt_task;

typedef char (*pt_task_fn)(struct pt *pt, int64_t timestamp, struct pt_task *task);

typedef struct pt_task {
  struct pt pt;
  struct pt_task *next;
  pt_task_fn func;
  void *udata;
  char is_active;
  int maxfd;
} pt_task_t;

int schedmod_pt_create(pt_task_fn fn, void *udata);
int schedmod_pt_remove(pt_task_t *task);
int schedmod_main();

extern fd_set g_select_result;

int schedmod_has_data(int *in_fds, int **out_fds);

#endif // __SCHEDULERMODULE_SCHEDULER_H__
