/// <!-- path: src/AppModule/command/daemon.c -->
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "cofyc/argparse.h"
#include "rxi/log.h"

#include "CliModule/common.h"
#include "config.h"
#include "AppModule/command/daemon.h"
#include "AppModule/plugin.h"

static pt_task_t *tasks = NULL;
static size_t task_count = 0;
static size_t task_cap = 0;
static int pt_running = 1;

int pt_task_has_data(pt_task_t *task, int *out_fd) {
  if (!task || !out_fd || task->read_fds_count == 0)
    return -1;
  *out_fd = -1;
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
  task->state = PT_WAITING;
  task_count++;

  return task;
}

void appmodule_pt_stop(void) {
  pt_running = 0;
}

static int64_t get_timestamp_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

static void scheduler_run(void) {
  fd_set read_fds;
  int maxfd = -1;

  for (;;) {
    if (!pt_running) break;

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

    if (n > 0) {
      for (size_t i = 0; i < task_count; i++) {
        pt_task_t *task = &tasks[i];
        task->state = PT_SCHEDULE(task->func(&task->pt, timestamp, task));
      }
    } else {
      for (size_t i = 0; i < task_count; i++) {
        pt_task_t *task = &tasks[i];
        task->state = PT_SCHEDULE(task->func(&task->pt, timestamp, task));
      }
    }

    for (size_t i = 0; i < task_count; ) {
      pt_task_t *task = &tasks[i];
      if (task->state == PT_EXITED || task->state == PT_ENDED) {
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

/// # DAEMON
/// **daemon** is the command that runs the SIP PBX server. It has no subcommands, only local options.
///
/// **Synopsis**
///
/// **upbx** [global options] **daemon** [options]
///
/// **Description**
///
/// Run the SIP PBX daemon: extension and trunk REGISTER handling, INVITE routing, built-in RTP relay, and optional plugins. Loads config (see global `-f`), binds the SIP UDP socket, and serves until the process is stopped.
///
/// **Options**
///
/// `-d`, `--daemonize`  
///   Run in background: double fork, detach from terminal, close stdin/stdout/stderr. Use for production or when started by an init system.
///
/// `-D`, `--no-daemonize`  
///   Force foreground. Overrides **daemonize=1** in the **[upbx]** config section. Use when you want to keep the process attached to the terminal even if config says daemonize.
///
/// **Daemonize behaviour**
///
/// - By default the daemon runs in the **foreground**.
/// - It goes to the **background** only if **daemonize=1** is set in **[upbx]** **or** you pass `-d` / `--daemonize`.
/// - `-D` / `--no-daemonize` always forces foreground.
///
static const char *const daemon_usages[] = {
  "upbx daemon [options]",
  NULL,
};

static int do_daemonize(void) {
  pid_t pid = fork();
  if (pid < 0) {
    log_fatal("fork: %m");
    return -1;
  }
  if (pid > 0)
    _exit(0);
  if (setsid() < 0) {
    log_fatal("setsid: %m");
    _exit(1);
  }
  pid = fork();
  if (pid < 0) {
    log_fatal("fork: %m");
    _exit(1);
  }
  if (pid > 0)
    _exit(0);
  if (chdir("/") != 0) {
    /* non-fatal */
  }
  int fd;
  for (fd = 0; fd < 3; fd++)
    (void)close(fd);
  fd = open("/dev/null", O_RDWR);
  if (fd >= 0) {
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2)
      close(fd);
  }
  return 0;
}

int appmodule_cmd_daemon(int argc, const char **argv) {
  int daemonize_flag = 0;
  int no_daemonize_flag = 0;

  struct argparse argparse;
  struct argparse_option options[] = {
    OPT_HELP(),
    OPT_BOOLEAN('d', "daemonize", &daemonize_flag, "run in background", NULL, 0, 0),
    OPT_BOOLEAN('D', "no-daemonize", &no_daemonize_flag, "force foreground (overrides config daemonize=1)", NULL, 0, 0),
    OPT_END(),
  };
  argparse_init(&argparse, options, daemon_usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);

  int want_daemonize;
  if (no_daemonize_flag)
    want_daemonize = 0;
  else if (daemonize_flag)
    want_daemonize = 1;
  else
    want_daemonize = -1;

  const char *config_path = cli_config_path();
  upbx_config cfg;
  config_init(&cfg);
  if (config_path && config_path[0]) {
    int r = config_load(&cfg, config_path);
    if (r < 0) {
      log_fatal("cannot open config: %s", config_path);
      return 1;
    }
    if (r > 0) {
      char err_sec[256], err_key[256];
      config_last_parse_error(err_sec, sizeof(err_sec), err_key, sizeof(err_key));
      log_error("config parse error at line %d: unknown key '%s' in section '%s'", r, err_key[0] ? err_key : "(none)", err_sec[0] ? err_sec : "(none)");
      config_free(&cfg);
      return 1;
    }
    r = config_compile_trunk_rewrites(&cfg);
    if (r != 0) {
      log_error("trunk rewrite compile failed");
      config_free(&cfg);
      return 1;
    }
    if (want_daemonize < 0)
      want_daemonize = cfg.daemonize ? 1 : 0;
    log_info("config loaded from %s", config_path);
  } else {
    if (want_daemonize < 0)
      want_daemonize = 0;
  }

  if (want_daemonize && do_daemonize() != 0)
    return 1;

  global_cfg = &cfg;

  log_info("daemon starting");
  plugin_sync();

  plugin_start(&cfg);

  scheduler_run();

  plugin_stop();
  config_free(&cfg);
  return 0;
}
