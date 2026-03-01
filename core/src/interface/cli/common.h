#ifndef UDPHOLE_CLI_COMMON_H
#define UDPHOLE_CLI_COMMON_H

#include <stddef.h>
#include <stdio.h>

struct cli_command {
  void *next;
  const char *cmd;
  const char *desc;
  int (*fn)(int, const char **);
};

extern struct cli_command *cli_commands;

const char *cli_find_arg(int argc, const char **argv, const char *name);

size_t cli_collect_positional(int argc, const char **argv, int start,
    const char **out, size_t max_out);

void cli_set_config_path(const char *path);
const char *cli_config_path(void);

const char *cli_resolve_default_config(void);

int cli_get_output_width(int default_width);

void cli_print_wrapped(FILE *out, const char *text, int width, int left_col_width);

void cli_register_command(const char *name, const char *description, int (*fn)(int, const char **));
int cli_execute_command(int argc, const char **argv);

#endif