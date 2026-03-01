#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>

#include "rxi/log.h"
#include "domain/scheduler.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

pt_task_t *pt_first = NULL;
fd_set g_select_result;
static fd_set g_want_fds;

int domain_schedmod_pt_create(pt_task_fn fn, void *udata) {
  if (!fn) return 1;

  pt_task_t *node = calloc(1, sizeof(pt_task_t));
  node->next           = pt_first;
  node->func           = fn;
  node->udata          = udata;
  PT_INIT(&node->pt);
  node->is_active  = 1;
  pt_first = node;
  
  log_trace("scheduler: created task %p (func=%p, udata=%p), pt_first=%p", (void*)node, (void*)fn, udata, (void*)pt_first);

  return 0;
}

int domain_schedmod_pt_remove(pt_task_t *task) {
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

int domain_schedmod_has_data(int *in_fds, int **out_fds) {
  if (!in_fds || in_fds[0] == 0) return 0;
  log_trace("domain_schedmod_has_data: in_fds[0]=%d", in_fds[0]);

  for (int i = 1; i <= in_fds[0]; i++) {
    int fd = in_fds[i];
    if (fd >= 0) {
      FD_SET(fd, &g_want_fds);
    }
  }

  if (*out_fds) free(*out_fds);
  *out_fds = NULL;

  int count = 0;
  for (int i = 1; i <= in_fds[0]; i++) {
    if (in_fds[i] >= 0 && FD_ISSET(in_fds[i], &g_select_result)) {
      count++;
    }
  }

  if (count == 0) return 0;

  *out_fds = malloc(sizeof(int) * (count + 1));
  if (!*out_fds) return 0;

  (*out_fds)[0] = count;
  int idx = 1;
  for (int i = 1; i <= in_fds[0]; i++) {
    if (in_fds[i] >= 0 && FD_ISSET(in_fds[i], &g_select_result)) {
      (*out_fds)[idx++] = in_fds[i];
      FD_CLR(in_fds[i], &g_select_result);
    }
  }

  return count;
}

int domain_schedmod_main(void) {
  if (!pt_first) return 0;

  struct timeval tv;
  int maxfd = -1;

  for(;;) {
    maxfd = -1;
    for (int fd = 0; fd < FD_SETSIZE; fd++) {
      if (FD_ISSET(fd, &g_want_fds)) {
        if (fd > maxfd) maxfd = fd;
      }
    }


    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    select(maxfd + 1, &g_want_fds, NULL, NULL, &tv);
    log_trace("scheduler: select returned");

    struct timeval now;
    gettimeofday(&now, NULL);
    int64_t timestamp = (int64_t)now.tv_sec * 1000 + now.tv_usec / 1000;
    g_select_result = g_want_fds;

    FD_ZERO(&g_want_fds);

  pt_task_t *task = pt_first;
  while (task) {
    pt_task_t *next = task->next;
    log_trace("scheduler: about to run task %p (func=%p, is_active=%d)", (void*)task, (void*)task->func, task->is_active);
    task->is_active = PT_SCHEDULE(task->func(&task->pt, timestamp, task));
    log_trace("scheduler: task %p (func=%p) returned, is_active=%d, next=%p", (void*)task, (void*)task->func, task->is_active, (void*)next);
    if (!task->is_active) {
      log_trace("scheduler: removing inactive task %p", (void*)task);
      domain_schedmod_pt_remove(task);
    }
    task = next;
  }
  log_trace("scheduler: loop done, pt_first=%p", (void*)pt_first);

    if (!pt_first) break;
  }

  return 0;
}