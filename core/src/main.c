#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>

#include "cofyc/argparse.h"
#include "rxi/log.h"

#include "CliModule/setup.h"
#include "CliModule/execute_command.h"
#include "CliModule/common.h"

#ifdef __cplusplus
}
#endif

/* Optional AppModule (daemon command) - call from main after climodule_setup if linked */
extern void appmodule_setup(void);

static const char *const usages[] = {
  "upbx [global] command [local]",
  "upbx list-commands",
  NULL,
};

/* Log file state for --log and SIGHUP re-open */
static FILE *log_file;
static char *log_path;
static volatile sig_atomic_t sighup_received;

static void logfile_callback(log_Event *ev) {
  if (sighup_received && log_path && log_file) {
    sighup_received = 0;
    fclose(log_file);
    log_file = fopen(log_path, "a");
  }
  if (log_file) {
    char buf[64];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ev->time)] = '\0';
    fprintf(log_file, "%s %-5s %s:%d: ", buf, log_level_string(ev->level), ev->file, ev->line);
    vfprintf(log_file, ev->fmt, ev->ap);
    fprintf(log_file, "\n");
    fflush(log_file);
  }
}

static void sighup_handler(int sig) {
  (void)sig;
  sighup_received = 1;
}

int main(int argc, const char **argv) {
  const char *loglevel = "info";
  const char *logfile_path = NULL;
  const char *config_path = NULL;

  climodule_setup();
  appmodule_setup();

  struct argparse argparse;
  struct argparse_option options[] = {
    OPT_HELP(),
    OPT_STRING('f', "config", &config_path, "config file path (default: auto-detect)", NULL, 0, 0),
    OPT_STRING('v', "verbosity", &loglevel, "log verbosity: fatal,error,warn,info,debug,trace (default: info)", NULL, 0, 0),
    OPT_STRING(0, "log", &logfile_path, "also write log to file (SIGHUP reopens for logrotate)", NULL, 0, 0),
    OPT_END(),
  };
  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);
  if (argc < 1) {
    argparse_usage(&argparse);
    return 1;
  }

  /* Resolve config path: explicit -f, then default locations */
  if (!config_path || !config_path[0])
    config_path = cli_resolve_default_config();
  cli_set_config_path(config_path);

  int level = LOG_INFO;
  if (0) {
    (void)0;
  } else if (!strcasecmp(loglevel, "trace")) {
    level = LOG_TRACE;
  } else if (!strcasecmp(loglevel, "debug")) {
    level = LOG_DEBUG;
  } else if (!strcasecmp(loglevel, "info")) {
    level = LOG_INFO;
  } else if (!strcasecmp(loglevel, "warn")) {
    level = LOG_WARN;
  } else if (!strcasecmp(loglevel, "error")) {
    level = LOG_ERROR;
  } else if (!strcasecmp(loglevel, "fatal")) {
    level = LOG_FATAL;
  } else {
    fprintf(stderr, "Unknown log level: %s\n", loglevel);
    return 1;
  }
  log_set_level(level);
  setvbuf(stderr, NULL, _IOLBF, 0); /* line-buffered so daemon startup lines appear immediately */

  log_file = NULL;
  log_path = NULL;
  sighup_received = 0;

  if (logfile_path && logfile_path[0]) {
    log_path = strdup(logfile_path);
    log_file = fopen(log_path, "a");
    if (log_file) {
      log_add_callback(logfile_callback, log_path, level);
      signal(SIGHUP, sighup_handler);
    } else {
      fprintf(stderr, "Could not open log file: %s\n", logfile_path);
      free(log_path);
      log_path = NULL;
    }
  }

  return climodule_execute_command(argc, argv);
}
