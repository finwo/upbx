#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "cofyc/argparse.h"
#include "rxi/log.h"

#include "CliModule/common.h"
#include "config.h"
#include "AppModule/command/daemon.h"
#include "AppModule/plugin.h"
#include "AppModule/sip_server.h"

static const char *const daemon_usages[] = {
  "upbx daemon [options]",
  NULL,
};

static int do_daemonize(void) {
  pid_t pid = fork();
  if (pid < 0) {
    log_error("fork: %m");
    return -1;
  }
  if (pid > 0)
    _exit(0);
  if (setsid() < 0) {
    log_error("setsid: %m");
    _exit(1);
  }
  pid = fork();
  if (pid < 0) {
    log_error("fork: %m");
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
  const char *config_path = NULL;
  int daemonize_flag = 0;
  int no_daemonize_flag = 0;

  struct argparse argparse;
  struct argparse_option options[] = {
    OPT_HELP(),
    OPT_STRING('f', "config", &config_path, "config file path", NULL, 0, 0),
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

  upbx_config cfg;
  config_init(&cfg);
  if (config_path && config_path[0]) {
    int r = config_load(&cfg, config_path);
    if (r < 0) {
      log_error("cannot open config: %s", config_path);
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

  log_info("daemon starting");
  plugin_start(&cfg);
  log_info("plugins started");

  void *av[1];
  av[0] = &cfg;
  daemon_root(1, av);
  /* never returns */

  plugin_stop();
  config_free(&cfg);
  return 0;
}