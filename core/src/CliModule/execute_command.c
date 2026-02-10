#include <stdio.h>
#include <string.h>

#include "common.h"

int climodule_execute_command(int argc, const char **argv) {
  struct climodule_command *cmd = climodule_commands;

  while(cmd) {
    if (!strcmp(cmd->cmd, argv[0])) return cmd->fn(argc, argv);
    cmd = cmd->next;
  }

  fprintf(stderr, "Unknown command: %s\n", argv[0]);
  return 1;
}
