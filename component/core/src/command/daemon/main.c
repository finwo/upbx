#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include "command/command.h"
#include "config/config.h"
#include "user/user.h"
#include "protocol/protocol.h"
#include "finwo/socket-util.h"
#include "finwo/scheduler.h"
#include "rxi/log.h"

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static int shutdown_watchdog(int64_t ts, struct pt_task *pt) {
    (void)ts;
    (void)pt;
    if (!g_running) {
        /* Null out the task list so sched_main exits on next iteration */
        extern pt_task_t *pt_first;
        pt_first = NULL;
        return SCHED_DONE;
    }
    return SCHED_RUNNING;
}

static char *find_default_config(void) {
    struct stat st;
    if (stat("/etc/upbx.conf", &st) == 0) return strdup("/etc/upbx.conf");
    if (stat("/etc/upbx", &st) == 0 && S_ISDIR(st.st_mode)) return strdup("/etc/upbx");
    return NULL;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s daemon [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --config <file>    Configuration file (default: /etc/upbx.conf)\n");
    fprintf(stderr, "  -h, --help             Show this help\n");
}

int cmd_daemon(int argc, const char **argv) {
    const char *config_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: -c requires a path\n"); return 1; }
            config_path = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (!config_path) config_path = find_default_config();
    if (!config_path) {
        fprintf(stderr, "Error: no config file specified and no default found\n");
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART so select() returns EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct upbx_config *config = upbx_config_load(config_path);
    if (!config) {
        fprintf(stderr, "daemon: failed to load config from %s\n", config_path);
        return 1;
    }

    struct upbx_user_registry *user_reg = upbx_user_registry_create();
    for (struct upbx_user_config *uc = config->users; uc; uc = uc->next) {
        upbx_user_registry_add(user_reg, uc->username, uc->secret, uc->pubkey_hex);
    }

    struct upbx_protocol_ctx *protocol = upbx_protocol_create();
    protocol->config = config;
    protocol->user_reg = user_reg;

    int count = 0;
    int *arrays[16] = {0};
    for (struct upbx_listen_addr *la = config->listen_addrs; la && count < 16; la = la->next) {
        int *fds = NULL;
        if (la->scheme && strcmp(la->scheme, "unix") == 0) {
            fds = unix_listen(la->path, SOCK_STREAM, NULL);
        } else {
            fds = tcp_listen(la->url, NULL, NULL);
        }
        if (fds && fds[0] > 0) {
            arrays[count++] = fds;
        }
    }
    int *listen_fds = merge_fd_arrays(arrays, count);
    protocol->listen_fds = listen_fds;

    upbx_protocol_start(protocol);
    sched_create(shutdown_watchdog, NULL);

    printf("UPBX core running. Press Ctrl+C to stop.\n");
    fflush(stdout);

    sched_main();

    upbx_protocol_free(protocol);
    upbx_user_registry_free(user_reg);
    upbx_config_free(config);

    printf("UPBX stopped.\n");
    return 0;
}

void __attribute__((constructor)) cmd_daemon_setup(void) {
    struct cmd_struct *cmd = calloc(1, sizeof(struct cmd_struct));
    cmd->next = commands;
    cmd->fn = cmd_daemon;
    static const char *add_names[] = {"daemon", NULL};
    cmd->name = add_names;
    cmd->display = "daemon";
    cmd->description = "Run the UPBX core daemon";
    cmd->help_text = "";
    commands = cmd;
}
