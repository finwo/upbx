#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "register_command.h"

void climodule_register_command(
  const char *name,
  const char *description,
  int (*fn)(int, const char **)
) {
  struct climodule_command *cmd = malloc(sizeof(struct climodule_command));
  cmd->next = climodule_commands;
  cmd->cmd  = strdup(name);
  cmd->desc = strdup(description);
  cmd->fn   = fn;
  climodule_commands = cmd;
}
