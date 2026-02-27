#include <stdio.h>
#include <string.h>

#include "config.h"
#include "CliModule/common.h"
#include "cofyc/argparse.h"
#include "AppModule/command/completion.h"

static const char *const completion_usages[] = {
  "upbx completion [shell]",
  NULL,
};

int appmodule_cmd_completion(int argc, const char **argv) {
  const char *shell = "bash";
  
  struct argparse argparse;
  struct argparse_option options[] = {
    OPT_HELP(),
    OPT_STRING(0, "shell", &shell, "shell type: bash or zsh", NULL, 0, 0),
    OPT_END(),
  };
  argparse_init(&argparse, options, completion_usages, ARGPARSE_STOP_AT_NON_OPTION);
  argc = argparse_parse(&argparse, argc, argv);
  
  if (argc > 1) {
    fprintf(stderr, "too many arguments\n");
    return 1;
  }
  
  if (strcmp(shell, "bash") == 0) {
    printf("_upbx() {\n");
    printf("  local cur prev\n");
    printf("  COMPREPLY=()\n");
    printf("  cur=${COMP_WORDS[COMP_CWORD]}\n");
    printf("  prev=${COMP_WORDS[COMP_CWORD-1]}\n");
    printf("  case $prev in\n");
    printf("    upbx)\n");
    printf("      COMPREPLY=( $(compgen -W 'daemon completion' -- $cur) )\n");
    printf("      ;;\n");
    printf("  esac\n");
    printf("  return 0\n");
    printf("}\n");
    printf("complete -F _upbx upbx\n");
  } else if (strcmp(shell, "zsh") == 0) {
    printf("#compdef upbx\n");
    printf("_upbx() {\n");
    printf("  local -a commands\n");
    printf("  commands=(\n");
    printf("    'daemon:Run the UPBX daemon'\n");
    printf("    'completion:Output shell completion'\n");
    printf("  )\n");
    printf("  _describe 'command' commands\n");
    printf("}\n");
    printf("_upbx \"$@\"\n");
  } else {
    fprintf(stderr, "unsupported shell: %s\n", shell);
    return 1;
  }
  
  return 0;
}
