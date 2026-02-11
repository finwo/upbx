#ifndef __CLIMODULE_COMMON_H__
#define __CLIMODULE_COMMON_H__

#include <stddef.h>
#include <stdio.h>

struct climodule_command {
  void *next;
  const char *cmd;
  const char *desc;
  int (*fn)(int, const char **);
};

extern struct climodule_command *climodule_commands;

/* Find the value of a named argument (e.g. "--name" "value"). Returns NULL if not found. */
const char *cli_find_arg(int argc, const char **argv, const char *name);

/* Collect positional arguments (those not part of --flag value pairs).
 * Scans argv[start..argc), skipping --flag value pairs. Returns count, fills out[]. */
size_t cli_collect_positional(int argc, const char **argv, int start,
    const char **out, size_t max_out);

/* Set/get the global config file path (resolved from -f or default locations). */
void cli_set_config_path(const char *path);
const char *cli_config_path(void);

/* Resolve default config path by checking standard locations:
 *   $HOME/.config/upbx.conf, $HOME/.upbx.conf, /etc/upbx/upbx.conf, /etc/upbx.conf
 * Returns pointer to a static buffer, or NULL if no config found. */
const char *cli_resolve_default_config(void);

/* Get terminal width for stdout (TIOCGWINSZ when stdout is a tty). Returns default_width if not a tty or ioctl fails. */
int cli_get_output_width(int default_width);

/* Word-wrap text to stream. Does not mutate text (works on a copy).
 * width: total line width.
 * left_col_width: on first line we assume this many columns are already used (e.g. command name); continuation lines are indented by this many spaces. Use 0 for full-width (e.g. paragraphs). */
void cli_print_wrapped(FILE *out, const char *text, int width, int left_col_width);

#endif // __CLIMODULE_COMMON_H__
