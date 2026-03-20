#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include "command/command.h"
#include "config/config.h"
#include "trunk/trunk.h"
#include "backbone/backbone.h"
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
        extern pt_task_t *pt_first;
        pt_first = NULL;
        return SCHED_DONE;
    }
    return SCHED_RUNNING;
}

static char *find_default_config(void) {
    struct stat st;
    if (stat("/etc/upbx-trk.conf", &st) == 0) return strdup("/etc/upbx-trk.conf");
    if (stat("/etc/upbx", &st) == 0 && S_ISDIR(st.st_mode)) return strdup("/etc/upbx");
    return NULL;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s daemon [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c, --config <file>    Configuration file (default: /etc/upbx-trk.conf)\n");
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
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct trk_config *config = trk_config_load(config_path);
    if (!config) {
        fprintf(stderr, "daemon: failed to load config from %s\n", config_path);
        return 1;
    }

    /* Create trunk state */
    struct trunk_state *trunk = trunk_create(config);

    /* Bind SIP UDP socket */
    char sip_addr[64];
    snprintf(sip_addr, sizeof(sip_addr), ":%d", config->sip_port);
    int *sip_fds = udp_recv(sip_addr, NULL, "5061");
    if (!sip_fds || sip_fds[0] < 1) {
        fprintf(stderr, "daemon: failed to bind SIP UDP socket on port %d\n", config->sip_port);
        return 1;
    }
    trunk->sip_fds = sip_fds;

    /* Start SIP receive task */
    trunk->sip_task = sched_create(trunk_sip_recv_task, trunk);

    /* Start backbone connection (if configured) */
    struct backbone_state *backbone = NULL;
    if (config->backbones) {
        backbone = backbone_create(config, trunk);
        trunk->backbone = backbone;
    }

    /* Start delay timer task */
    trunk->delay_task = sched_create(trunk_delay_task, trunk);

    /* Shutdown watchdog */
    sched_create(shutdown_watchdog, NULL);

    printf("UPBX trunk running on port %d. Press Ctrl+C to stop.\n", config->sip_port);
    fflush(stdout);

    sched_main();

    if (backbone) backbone_free(backbone);
    trunk_free(trunk);
    free(sip_fds);
    trk_config_free(config);

    printf("UPBX trunk stopped.\n");
    return 0;
}

void __attribute__((constructor)) cmd_daemon_setup(void) {
    struct cmd_struct *cmd = calloc(1, sizeof(struct cmd_struct));
    cmd->next = commands;
    cmd->fn = cmd_daemon;
    static const char *add_names[] = {"daemon", NULL};
    cmd->name = add_names;
    cmd->display = "daemon";
    cmd->description = "Run the UPBX trunk daemon";
    cmd->help_text = "";
    commands = cmd;
}
