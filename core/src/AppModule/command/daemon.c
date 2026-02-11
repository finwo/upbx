/// <!-- path: src/AppModule/command/daemon.c -->
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

  log_info("daemon starting");
  plugin_sync();

  void *av[1];
  av[0] = &cfg;
  daemon_root(1, av);
  /* never returns */

  plugin_stop();
  config_free(&cfg);
  return 0;
}