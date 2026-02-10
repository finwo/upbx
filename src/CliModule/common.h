#ifndef __CLIMODULE_COMMON_H__
#define __CLIMODULE_COMMON_H__

#include <stddef.h>

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

#endif // __CLIMODULE_COMMON_H__
