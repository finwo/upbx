#include <stdio.h>
#include <string.h>

#include "interface/cli/common.h"
#include "interface/cli/command/list_commands.h"

int cli_cmd_list_commands(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  int len;
  int name_longest = 0;
  struct cli_command *cmd = cli_commands;
  while(cmd) {
    len = (int)strlen(cmd->cmd);
    if (len > name_longest) { name_longest = len; }
    cmd = cmd->next;
  }

  int width = cli_get_output_width(80);
  int left_col = name_longest + 3;

  printf("\n");
  printf("Available commands:\n");
  cmd = cli_commands;
  while (cmd) {
    printf("\n  %*s ", name_longest, cmd->cmd);
    cli_print_wrapped(stdout, cmd->desc, width, left_col);
    cmd = cmd->next;
  }
  printf("\n\n");

  return 0;
}