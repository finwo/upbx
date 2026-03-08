#include "interface/cli/command/daemon.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cofyc/argparse.h"
#include "common/scheduler.h"
#include "domain/config.h"
#include "domain/pbx/media_proxy.h"
#include "domain/pbx/pbx.h"
#include "infrastructure/config.h"
#include "interface/api/server.h"
#include "interface/cli/common.h"
#include "rxi/log.h"

void pbx_media_proxy_init(void);
void pbx_init(void);

static void udphole_client_init_global(void) {
  pbx_media_proxy_init();
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
/// Run the SIP PBX daemon: extension and trunk REGISTER handling, INVITE routing, and optional plugins. Loads config
/// (see global `-f`), binds the SIP UDP socket, and serves until the process is stopped.
///
/// **Options**
///
/// `-d`, `--daemonize`
///   Run in background: double fork, detach from terminal, close stdin/stdout/stderr. Use for production or when
///   started by an init system.
///
/// `-D`, `--no-daemonize`
///   Force foreground. Overrides **daemonize=1** in the **[upbx]** config section. Use when you want to keep the
///   process attached to the terminal even if config says daemonize.
///
/// **Daemonize behaviour**
///
/// - By default the daemon runs in the **foreground**.
/// - It goes to the **background** only if **daemonize=1** is set in **[upbx]** **or** you pass `-d` / `--daemonize`.
/// - `-D` / `--no-daemonize` always forces foreground.
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
  if (pid > 0) _exit(0);
  if (setsid() < 0) {
    log_fatal("setsid: %m");
    _exit(1);
  }
  pid = fork();
  if (pid < 0) {
    log_fatal("fork: %m");
    _exit(1);
  }
  if (pid > 0) _exit(0);
  if (chdir("/") != 0) {
    /* non-fatal */
  }
  int fd;
  for (fd = 0; fd < 3; fd++) (void)close(fd);
  fd = open("/dev/null", O_RDWR);
  if (fd >= 0) {
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) close(fd);
  }
  return 0;
}

int cli_cmd_daemon(int argc, const char **argv) {
  int daemonize_flag    = 0;
  int no_daemonize_flag = 0;

  struct argparse        argparse;
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_BOOLEAN('d', "daemonize", &daemonize_flag, "run in background", NULL, 0, 0),
      OPT_BOOLEAN('D', "no-daemonize", &no_daemonize_flag, "force foreground (overrides config daemonize=1)", NULL, 0,
                  0),
      OPT_END(),
  };
  argparse_init(&argparse, options, daemon_usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);

  if ((!no_daemonize_flag) && (daemonize_flag || 0)) {
    do_daemonize();
  }

  config_init();

  udphole_client_init_global();

  pbx_init();

  sched_create(api_server_pt, NULL);
  sched_create(sip_transport_udp_pt, NULL);
  sched_create(registration_cleanup_pt, NULL);
  sched_create(addrmap_cleanup_pt, NULL);
  sched_create(udphole_keepalive_pt, NULL);

  log_info("upbx: daemon started");

  return sched_main();
}
