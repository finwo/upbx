#include <stdio.h>
#include <stdlib.h>

#include "command/command.h"

int cmd_daemon(int argc, const char **argv) {
  return 42;
}

void __attribute__((constructor)) cmd_daemon_setup(void) {
  struct cmd_struct *cmd = calloc(1, sizeof(struct cmd_struct));
  if (!cmd) {
    fprintf(stderr, "Failed to allocate memory for add command\n");
    return;
  }
  cmd->next                      = commands;
  cmd->fn                        = cmd_daemon;
  static const char *add_names[] = {"daemon", NULL};
  cmd->name                      = add_names;
  cmd->display                   = "daemon";
  cmd->description               = "Run the main daemon";
  cmd->help_text = "";
  commands = cmd;
}
