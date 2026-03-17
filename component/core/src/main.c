#include <stdio.h>
#include <string.h>

#include "cofyc/argparse.h"
#include "command/command.h"

struct cmd_struct *commands = NULL;

static const char *const usages[] = {
    "upbx [global options] <command> [command options]",
    NULL,
};

static void print_global_usage(void) {
  printf("Usage: upbx [global options] <command> [command options]\n");
  printf("\n");
  printf("Global options:\n");
  printf("  n/a\n");
  printf("\n");
  printf("Commands:\n");

  struct cmd_struct *cmd = commands;
  while (cmd) {
    printf("  %-16s %s\n", cmd->display ? cmd->display : cmd->name[0], cmd->description ? cmd->description : "");
    cmd = cmd->next;
  }

  printf("\n");
  printf("Help topics:\n");
  printf("  global          This help text\n");

  cmd = commands;
  while (cmd) {
    printf("  %-16s More detailed explanation on the %s command\n", cmd->name[0], cmd->name[0]);
    cmd = cmd->next;
  }
}

int main(int argc, const char **argv) {
  struct argparse        argparse;
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_END(),
  };
  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);
  if (argc < 1) {
    print_global_usage();
    return 0;
  }

  /* Try to run command with args provided. */
  struct cmd_struct *cmd = commands;
  while (cmd) {
    const char **name = cmd->name;
    while (*name) {
      if (!strcmp(*name, argv[0])) {
        goto found;
      }
      name++;
    }
    cmd = cmd->next;
  }
found:

  if (cmd) {
    return cmd->fn(argc, argv);
  } else {
    fprintf(stderr, "Unknown command: %s\n", argv[0]);
    return 1;
  }

  return 0;
}
