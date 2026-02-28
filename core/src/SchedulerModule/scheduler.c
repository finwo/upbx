#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>

#include "scheduler.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

pt_task_t *pt_first = NULL;
fd_set g_select_result;

int schedmod_pt_create(pt_task_fn fn, void *udata) {
  if (!fn) return 1;

  pt_task_t *node = calloc(1, sizeof(pt_task_t));
  node->next           = pt_first;
  node->func           = fn;
  node->udata          = udata;
  PT_INIT(&node->pt);
  node->read_fds   = NULL;
  node->is_active  = 1;
  pt_first = node;

  return 0;
}

int schedmod_pt_remove(pt_task_t *task) {
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
      if (curr->read_fds) free(curr->read_fds);
      free(curr);
      return 0;
    }
    prev = curr;
    curr = curr->next;
  }

  return 1;
}

int schedmod_pt_has_data(pt_task_t *task, int *out_fd) {
  if (!task || !out_fd || !task->read_fds || task->read_fds[0] == 0)
    return -1;

  *out_fd = -1;

  for (int i = 1; i <= task->read_fds[0]; i++) {
    int fd = task->read_fds[i];
    if (fd >= 0 && FD_ISSET(fd, &g_select_result)) {
      *out_fd = fd;
      return 0;
    }
  }
  return -1;
}

int schedmod_main() {
  if (!pt_first) return 0;

  struct timeval tv;
  int maxfd = -1;

  for(;;) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    pt_task_t *task = pt_first;
    while (task) {
      task->maxfd = -1;
      if (task->read_fds) {
        for (int i = 1; i <= task->read_fds[0]; i++) {
          int fd = task->read_fds[i];
          if (fd >= 0) {
            FD_SET(fd, &read_fds);
            if (fd > maxfd) maxfd = fd;
            if (task->maxfd < fd) task->maxfd = fd;
          }
        }
      }
      task = task->next;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    select(maxfd + 1, &read_fds, NULL, NULL, &tv);

    struct timeval now;
    gettimeofday(&now, NULL);
    int64_t timestamp = (int64_t)now.tv_sec * 1000 + now.tv_usec / 1000;
    g_select_result = read_fds;

    task = pt_first;
    while (task) {
      pt_task_t *next = task->next;
      task->is_active = PT_SCHEDULE(task->func(&task->pt, timestamp, task));
      if (!task->is_active) {
        schedmod_pt_remove(task);
      }
      task = next;
    }

    if (!pt_first) break;
  }

  return 0;
}
