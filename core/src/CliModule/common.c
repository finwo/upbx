#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "CliModule/common.h"

#ifndef NULL
#define NULL (void*)0
#endif

struct climodule_command *climodule_commands = NULL;

static const char *global_config_path = NULL;

const char *cli_find_arg(int argc, const char **argv, const char *name) {
  for (int i = 0; i < argc - 1; i++)
    if (strcmp(argv[i], name) == 0)
      return argv[i + 1];
  return NULL;
}

size_t cli_collect_positional(int argc, const char **argv, int start,
    const char **out, size_t max_out) {
  size_t n = 0;
  for (int i = start; i < argc && n < max_out; i++) {
    if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] != '\0') {
      i++; /* skip value of --flag */
      continue;
    }
    out[n++] = argv[i];
  }
  return n;
}

void cli_set_config_path(const char *path) {
  global_config_path = path;
}

const char *cli_config_path(void) {
  return global_config_path;
}

const char *cli_resolve_default_config(void) {
  static char buf[1024];
  const char *home = getenv("HOME");
  if (home) {
    snprintf(buf, sizeof(buf), "%s/.config/upbx.conf", home);
    if (access(buf, R_OK) == 0) return buf;
    snprintf(buf, sizeof(buf), "%s/.upbx.conf", home);
    if (access(buf, R_OK) == 0) return buf;
  }
  if (access("/etc/upbx/upbx.conf", R_OK) == 0) return "/etc/upbx/upbx.conf";
  if (access("/etc/upbx.conf", R_OK) == 0) return "/etc/upbx.conf";
  return NULL;
}

int cli_get_output_width(int default_width) {
  if (!isatty(STDOUT_FILENO))
    return default_width;
  struct winsize w;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) < 0 || w.ws_col <= 0)
    return default_width;
  return (int)w.ws_col;
}

void cli_print_wrapped(FILE *out, const char *text, int width, int left_col_width) {
  if (!text || width <= left_col_width)
    return;
  char *copy = strdup(text);
  if (!copy)
    return;
  int len = left_col_width;
  char *tok = strtok(copy, " ");
  while (tok) {
    int toklen = (int)strlen(tok);
    if (len + 1 + toklen > width) {
      fprintf(out, "\n%*s", left_col_width, "");
      len = left_col_width;
    }
    if (len > left_col_width)
      fputc(' ', out);
    fputs(tok, out);
    len += (len > left_col_width ? 1 : 0) + toklen;
    tok = strtok(NULL, " ");
  }
  free(copy);
}
