#ifndef UDPHOLE_SCHEDULER_H
#define UDPHOLE_SCHEDULER_H

#include <stdint.h>
#include <sys/select.h>

#define SCHED_RUNNING 0
#define SCHED_DONE    1
#define SCHED_ERROR   2

struct pt_task;

typedef int (*pt_task_fn)(int64_t timestamp, struct pt_task *task);

typedef struct pt_task {
  struct pt_task *next;
  pt_task_fn      func;
  void           *udata;
  char            is_active;
  int             maxfd;
} pt_task_t;

int sched_create(pt_task_fn fn, void *udata);
int sched_remove(pt_task_t *task);
int sched_main(void);

int sched_has_data(int *in_fds);

#endif  // UDPHOLE_SCHEDULER_H
