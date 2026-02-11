/// <!-- path: src/main.c -->
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
#include "config.h"

#ifdef __cplusplus
}
#endif

/* Optional AppModule (daemon command) - call from main after climodule_setup if linked */
extern void appmodule_setup(void);

#define INCBIN_SILENCE_BITCODE_WARNING
#include "graphitemaster/incbin.h"
INCTXT(License, "LICENSE.md");

/// # GLOBAL OPTIONS
/// Global options apply to every **upbx** run. They must appear **before** the command name; everything after the command is passed to that command.
///
/// **Synopsis**
///
/// **upbx** [global options] &lt;command&gt; [command options and arguments]  
/// **upbx** `-h` | `--help`  
/// **upbx** `--license`  
/// **upbx** `list-commands`
///
/// **Options**
///
/// `-h`, `--help`  
///   Print the usage strings and options for this layer to stderr and exit. Shows the usages and the global options; does not list commands.
///
/// `-f`, `--config` &lt;path&gt;  
///   Config file path. If omitted, the following are tried in order: **$HOME/.config/upbx.conf**, **$HOME/.upbx.conf**, **/etc/upbx/upbx.conf**, **/etc/upbx.conf**. Used by all commands that read or write config (daemon, extension, trunk, api-user, completion).
///
/// `-v`, `--verbosity` &lt;level&gt;  
///   Log verbosity: **fatal**, **error**, **warn**, **info**, **debug**, **trace**. Default: **info**. Applies to the daemon and any command that uses the logging subsystem.
///
/// `--log` &lt;path&gt;  
///   In addition to stderr, append logs to the given file. Send SIGHUP to the process to reopen the file (e.g. after logrotate). Useful when running the daemon.
///
/// `--license`  
///   Print the full license text to stdout (paragraphs and list, wrapped to terminal width) and exit with 0. No config is loaded and no command is run.
///
/// **Top-level commands**
///
/// - [**daemon**](#daemon) — Run the SIP PBX server.
/// - [**extension**](#extension) — Manage extensions in the config file.
/// - [**trunk**](#trunk) — Manage SIP trunks in the config file.
/// - [**api-user**](#api-user) — Manage API users in the config file.
/// - [**completion**](#completion) — Output shell completion scripts for bash or zsh.
/// - [**list-commands**](#list-commands) — List available commands and short descriptions.
///
static const char *const usages[] = {
  "upbx [global] command [local]",
  "upbx list-commands",
  "upbx --license",
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

#define MARKER_PARAGRAPH "<!-- paragraph -->"
#define MARKER_LIST_START "<!-- list:start -->"
#define MARKER_LIST_END   "<!-- list:end -->"

static void skip_whitespace(const char **p) {
  while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') (*p)++;
}

static void print_license_paragraph(const char *start, const char *end, int width) {
  if (start >= end) return;
  while (start < end && (*start == ' ' || *start == '\n' || *start == '\r')) start++;
  while (end > start && (end[-1] == ' ' || end[-1] == '\n' || end[-1] == '\r')) end--;
  if (start >= end) return;
  static char buf[4096];
  size_t n = (size_t)(end - start);
  if (n >= sizeof(buf)) n = sizeof(buf) - 1;
  memcpy(buf, start, n);
  buf[n] = '\0';
  for (size_t i = 0; i < n; i++)
    if (buf[i] == '\n') buf[i] = ' ';
  cli_print_wrapped(stdout, buf, width, 0);
  fputc('\n', stdout);
}

static void print_license_list(const char *start, const char *end, int width) {
  const int left_col = 5;
  const char *p = start;
  while (p < end) {
    skip_whitespace(&p);
    if (p >= end) break;
    if (*p < '0' || *p > '9') { p++; continue; }
    const char *num_start = p;
    while (p < end && *p >= '0' && *p <= '9') p++;
    if (p >= end || *p != '.') continue;
    p++;
    skip_whitespace(&p);
    const char *text_start = p;
    const char *item_end = p;
    while (item_end < end) {
      const char *next = item_end;
      while (next < end && *next != '\n') next++;
      if (next < end) next++;
      if (next >= end) { item_end = end; break; }
      skip_whitespace(&next);
      if (next < end && *next >= '0' && *next <= '9') {
        const char *q = next;
        while (q < end && *q >= '0' && *q <= '9') q++;
        if (q < end && *q == '.') break;
      }
      item_end = next;
    }
    while (item_end > text_start && (item_end[-1] == ' ' || item_end[-1] == '\n' || item_end[-1] == '\r')) item_end--;
    int num = atoi(num_start);
    fprintf(stdout, " %2d. ", num);
    static char buf[1024];
    size_t n = (size_t)(item_end - text_start);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, text_start, n);
    buf[n] = '\0';
    for (size_t i = 0; i < n; i++)
      if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
    cli_print_wrapped(stdout, buf, width, left_col);
    fputc('\n', stdout);
    p = item_end;
  }
}

static void cli_print_license(FILE *out, const char *text, int width) {
  const char *p = text;
  (void)out;
  while (*p) {
    const char *q = strstr(p, "<!-- ");
    if (!q) {
      print_license_paragraph(p, p + strlen(p), width);
      break;
    }
    if (q > p)
      print_license_paragraph(p, q, width);
    q += 5;
    if (strncmp(q, "paragraph -->", 13) == 0) {
      q += 13;
      skip_whitespace(&q);
      const char *r = strstr(q, "<!-- ");
      if (!r) r = q + strlen(q);
      print_license_paragraph(q, r, width);
      p = r;
      continue;
    }
    if (strncmp(q, "list:start -->", 14) == 0) {
      q += 14;
      skip_whitespace(&q);
      const char *r = strstr(q, "<!-- list:end -->");
      if (r)
        print_license_list(q, r, width);
      p = r ? r + 16 : q + strlen(q);
      continue;
    }
    const char *close = strchr(q, '>');
    p = close ? close + 1 : q + strlen(q);
  }
}

int main(int argc, const char **argv) {
  const char *loglevel = "info";
  const char *logfile_path = NULL;
  const char *config_path = NULL;
  static int license_flag = 0;

  climodule_setup();
  appmodule_setup();

  struct argparse argparse;
  struct argparse_option options[] = {
    OPT_HELP(),
    OPT_STRING('f', "config", &config_path, "config file path (default: auto-detect)", NULL, 0, 0),
    OPT_STRING('v', "verbosity", &loglevel, "log verbosity: fatal,error,warn,info,debug,trace (default: info)", NULL, 0, 0),
    OPT_STRING(0, "log", &logfile_path, "also write log to file (SIGHUP reopens for logrotate)", NULL, 0, 0),
    OPT_BOOLEAN(0, "license", &license_flag, "print license and exit", NULL, 0, 0),
    OPT_END(),
  };
  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);

  if (license_flag) {
    cli_print_license(stdout, (const char *)gLicenseData, cli_get_output_width(120));
    return 0;
  }

  if (argc < 1) {
    argparse_usage(&argparse);
    return 1;
  }

  /* Resolve config path: explicit -f, then default locations */
  if (!config_path || !config_path[0])
    config_path = cli_resolve_default_config();
  cli_set_config_path(config_path);
  config_set_path(config_path);

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
