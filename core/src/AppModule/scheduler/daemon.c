#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "rxi/log.h"
#include "common/pt.h"
#include "config.h"
#include "AppModule/scheduler/daemon.h"

static pt_task_t *tasks = NULL;
static size_t task_count = 0;
static size_t task_cap = 0;
static int pt_running = 1;
static fd_set g_select_result;

int pt_task_has_data(pt_task_t *task, int *out_fd) {
  if (!task || !out_fd || task->read_fds_count == 0)
    return -1;

  *out_fd = -1;

  for (int i = 0; i < task->read_fds_count; i++) {
    int fd = task->read_fds[i];
    if (fd >= 0 && FD_ISSET(fd, &g_select_result)) {
      *out_fd = fd;
      return 0;
    }
  }
  return -1;
}

pt_task_t *appmodule_pt_add(pt_task_fn func, void *udata) {
  if (!func) return NULL;

  if (task_count >= task_cap) {
    size_t new_cap = task_cap == 0 ? 4 : task_cap * 2;
    pt_task_t *new_tasks = realloc(tasks, new_cap * sizeof(pt_task_t));
    if (!new_tasks) {
      log_error("appmodule_pt_add: failed to allocate memory");
      return NULL;
    }
    tasks = new_tasks;
    task_cap = new_cap;
  }

  pt_task_t *task = &tasks[task_count];
  memset(task, 0, sizeof(*task));
  PT_INIT(&task->pt);
  task->udata = udata;
  task->func = func;
  task->read_fds = NULL;
  task->read_fds_count = 0;
  task->maxfd = -1;
  task->is_active = PT_WAITING;
  task_count++;

  return task;
}

void appmodule_pt_stop(void) {
  pt_running = 0;
}

void appmodule_pt_remove(pt_task_t *task) {
  if (!task) return;
  task->is_active = PT_EXITED;
}

static int64_t get_timestamp_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

static void sighup_handler(int sig) {
  (void)sig;
  config_trigger_reload();
}

static void handle_config_reload(void) {
  if (!config_is_reload_pending())
    return;

  log_info("sighup: reloading configuration");

  int r = config_reload();
  if (r != 0) {
    log_error("sighup: config reload failed with code %d", r);
  } else {
    log_info("sighup: config reloaded successfully");
  }
}

void scheduler_run(void) {
  fd_set read_fds;
  int maxfd = -1;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sighup_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGHUP, &sa, NULL);

  for (;;) {
    if (!pt_running) break;

    handle_config_reload();

    int64_t timestamp = get_timestamp_ms();

    FD_ZERO(&read_fds);
    maxfd = -1;

    for (size_t i = 0; i < task_count; i++) {
      pt_task_t *task = &tasks[i];
      task->maxfd = -1;
      for (int j = 0; j < task->read_fds_count; j++) {
        int fd = task->read_fds[j];
        if (fd >= 0) {
          FD_SET(fd, &read_fds);
          if (fd > maxfd) maxfd = fd;
          if (task->maxfd < fd) task->maxfd = fd;
        }
      }
    }

    struct timeval tv = { 0, 100000 };
    int n = select(maxfd + 1, &read_fds, NULL, NULL, &tv);
    timestamp = get_timestamp_ms();
    g_select_result = read_fds;

    if (n > 0) {
      for (size_t i = 0; i < task_count; i++) {
        pt_task_t *task = &tasks[i];
        task->is_active = PT_SCHEDULE(task->func(&task->pt, timestamp, task));
      }
    } else {
      for (size_t i = 0; i < task_count; i++) {
        pt_task_t *task = &tasks[i];
        task->is_active = PT_SCHEDULE(task->func(&task->pt, timestamp, task));
      }
    }

    for (size_t i = 0; i < task_count; ) {
      pt_task_t *task = &tasks[i];
      if (!task->is_active) {
        if (task->read_fds) free(task->read_fds);
        task_count--;
        if (i < task_count) {
          memmove(&tasks[i], &tasks[i + 1], (task_count - i) * sizeof(pt_task_t));
        }
      } else {
        i++;
      }
    }
  }
}

void scheduler_shutdown(void) {
  for (size_t i = 0; i < task_count; i++) {
    if (tasks[i].read_fds) free(tasks[i].read_fds);
  }
  free(tasks);
  tasks = NULL;
  task_count = 0;
  task_cap = 0;
}