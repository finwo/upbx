/// <!-- path: src/CliModule/command/list_commands.c -->
/// # LIST-COMMANDS
/// **list-commands** is the command that lists all available CLI commands and their short descriptions. It has no subcommands or options.
///
/// **Synopsis**
///
/// **upbx** [global options] **list-commands**
///
/// **Description**
///
/// Prints a two-column layout (command name, description). Use it to discover **daemon**, **extension**, **trunk**, **api-user**, **completion**, and any other registered commands.
///
#include <stdio.h>
#include <string.h>

#include "../common.h"
#include "list_commands.h"

int climodule_cmd_list_commands(int argc, const char **argv) {
  int len;
  int name_longest = 0;
  struct climodule_command *cmd = climodule_commands;
  while(cmd) {
    len = (int)strlen(cmd->cmd);
    if (len > name_longest) { name_longest = len; }
    cmd = cmd->next;
  }

  int width = cli_get_output_width(80);
  int left_col = name_longest + 3; /* "  " + name + " " */

  printf("\n");
  printf("Available commands:\n");
  cmd = climodule_commands;
  while (cmd) {
    printf("\n  %*s ", name_longest, cmd->cmd);
    cli_print_wrapped(stdout, cmd->desc, width, left_col);
    cmd = cmd->next;
  }
  printf("\n\n");

  return 0;
}
