#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../common.h"
#include "list_commands.h"

int climodule_cmd_list_commands(int argc, const char **argv) {

  // Detect name lenghts
  int name_longest = 0;
  int len, toklen;
  struct climodule_command *cmd = climodule_commands;
  while(cmd) {
    len = strlen(cmd->cmd);
    if (len > name_longest) { name_longest = len; }
    cmd = cmd->next;
  }

  // Get terminal width
  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

  // Print basic table
  printf("\n");
  printf("Available commands:\n");
  cmd = climodule_commands;
  char *desc, *tok;
  while(cmd) {
    len  = name_longest + 4;
    desc = strdup(cmd->desc);
    printf("\n  %*s ", name_longest, cmd->cmd);
    tok = strtok(desc, " ");
    do {
      if (!tok) break;
      toklen = strlen(tok);
      if (len + 1 + toklen >= w.ws_col) {
        printf("\n  %*s ", name_longest, "");
        len = name_longest + 4;
      }
      printf(" %s", tok);
      len += toklen + 1;
    } while((tok = strtok(NULL, " ")));
    cmd = cmd->next;
  }
  printf("\n\n");

  return 0;
}
