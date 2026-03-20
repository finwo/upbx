#include <stdio.h>
#include <string.h>
#include "cofyc/argparse.h"
#include "rxi/log.h"
#include "command/command.h"

struct cmd_struct *commands = NULL;

static const char *const usages[] = {
    "upbx-trk [global options] <command> [command options]",
    NULL,
};

static void print_global_usage(void) {
    printf("Usage: upbx-trk [global options] <command> [command options]\n");
    printf("\n");
    printf("Global options:\n");
    printf("  -v, --verbosity <level>  Log level: fatal,error,warn,info,debug,trace\n");
    printf("\n");
    printf("Commands:\n");
    struct cmd_struct *cmd = commands;
    while (cmd) {
        printf("  %-16s %s\n", cmd->display ? cmd->display : cmd->name[0],
               cmd->description ? cmd->description : "");
        cmd = cmd->next;
    }
    printf("\n");
}

int main(int argc, const char **argv) {
    char *loglevel = NULL;

    struct argparse argparse;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_STRING('v', "verbosity", &loglevel, "log level", NULL, 0, 0),
        OPT_END(),
    };
    argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
    argc = argparse_parse(&argparse, argc, argv);
    if (argc < 1) {
        print_global_usage();
        return 0;
    }

    int level = LOG_INFO;
    if (loglevel && !strcmp(loglevel, "trace")) level = LOG_TRACE;
    else if (loglevel && !strcmp(loglevel, "debug")) level = LOG_DEBUG;
    else if (loglevel && !strcmp(loglevel, "warn")) level = LOG_WARN;
    else if (loglevel && !strcmp(loglevel, "error")) level = LOG_ERROR;
    else if (loglevel && !strcmp(loglevel, "fatal")) level = LOG_FATAL;
    else if (loglevel) { fprintf(stderr, "Unknown log level: %s\n", loglevel); return 1; }
    log_set_level(level);

    struct cmd_struct *cmd = commands;
    while (cmd) {
        const char **name = cmd->name;
        while (*name) {
            if (!strcmp(*name, argv[0])) return cmd->fn(argc, argv);
            name++;
        }
        cmd = cmd->next;
    }

    fprintf(stderr, "Unknown command: %s\n", argv[0]);
    return 1;
}
