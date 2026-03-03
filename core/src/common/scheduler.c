#include "common/scheduler.h"

#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

pt_task_t    *pt_first = NULL;
fd_set        g_select_result;
static fd_set g_want_fds;

int sched_create(pt_task_fn fn, void *udata) {
  if (!fn) return 1;

  pt_task_t *node = calloc(1, sizeof(pt_task_t));
  node->next      = pt_first;
  node->func      = fn;
  node->udata     = udata;
  node->is_active = 1;
  pt_first        = node;

  return 0;
}

int sched_remove(pt_task_t *task) {
  if (!task) return 1;

  pt_task_t *curr = pt_first;
  pt_task_t *prev = NULL;

  while (curr) {
    if (curr == task) {
      if (prev) {
        prev->next = curr->next;
      } else {
        pt_first = curr->next;
      }
      free(curr);
      return 0;
    }
    prev = curr;
    curr = curr->next;
  }

  return 1;
}

int sched_has_data(int *in_fds) {
  if (!in_fds || in_fds[0] == 0) return -1;

  for (int i = 1; i <= in_fds[0]; i++) {
    int fd = in_fds[i];
    if (fd >= 0) {
      FD_SET(fd, &g_want_fds);
    }
  }

  for (int i = 1; i <= in_fds[0]; i++) {
    int fd = in_fds[i];
    if (fd >= 0 && FD_ISSET(fd, &g_select_result)) {
      FD_CLR(fd, &g_select_result);
      return fd;
    }
  }

  return -1;
}

int sched_main(void) {
  if (!pt_first) return 0;

  struct timeval tv;
  int            maxfd;

  for (;;) {
    maxfd = -1;
    for (int fd = 0; fd < FD_SETSIZE; fd++) {
      if (FD_ISSET(fd, &g_want_fds)) {
        if (fd > maxfd) maxfd = fd;
      }
    }

    if (maxfd < 0) {
      tv.tv_sec  = 0;
      tv.tv_usec = 100000;
      select(0, NULL, NULL, NULL, &tv);
    } else {
      tv.tv_sec  = 0;
      tv.tv_usec = 100000;
      select(maxfd + 1, &g_want_fds, NULL, NULL, &tv);
      g_select_result = g_want_fds;
      FD_ZERO(&g_want_fds);
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    int64_t timestamp = (int64_t)now.tv_sec * 1000 + now.tv_usec / 1000;

    pt_task_t *task = pt_first;
    while (task) {
      pt_task_t *next = task->next;
      task->is_active = (task->func(timestamp, task) == SCHED_RUNNING);
      if (!task->is_active) {
        sched_remove(task);
      }
      task = next;
    }

    if (!pt_first) break;
  }

  return 0;
}
