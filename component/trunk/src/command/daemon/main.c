#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include "command/command.h"
#include "config/config.h"
#include "trunk/trunk.h"
#include "backbone/backbone.h"
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

/* Detect local IP that would be used to reach target_host.
 * Uses a temporary UDP connect+getsockname trick. */
static void detect_listen_address(struct trunk_state *ts, const char *target_host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (!target_host || getaddrinfo(target_host, "5060", &hints, &res) != 0 || !res) {
        log_warn("trunk: failed to resolve %s for listen address detection", target_host ? target_host : "(null)");
        return;
    }

    int fd = socket(res->ai_family, SOCK_DGRAM, 0);
    if (fd < 0) { freeaddrinfo(res); return; }

    if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
        struct sockaddr_storage local;
        socklen_t local_len = sizeof(local);
        if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0) {
            if (local.ss_family == AF_INET) {
                struct sockaddr_in *la = (struct sockaddr_in *)&local;
                inet_ntop(AF_INET, &la->sin_addr, ts->listen_addr, sizeof(ts->listen_addr));
            } else if (local.ss_family == AF_INET6) {
                struct sockaddr_in6 *la = (struct sockaddr_in6 *)&local;
                inet_ntop(AF_INET6, &la->sin6_addr, ts->listen_addr, sizeof(ts->listen_addr));
            }
            log_info("trunk: listen address auto-detected: %s (from route to %s)",
                     ts->listen_addr, target_host);
        }
    }
    close(fd);
    freeaddrinfo(res);
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

    /* Set listen address for SDP/SIP headers */
    const char *target_host = config->target ? config->target->host : NULL;
    if (config->listen_address) {
        strncpy(trunk->listen_addr, config->listen_address, sizeof(trunk->listen_addr) - 1);
        log_info("trunk: listen address from config: %s", trunk->listen_addr);
    } else if (target_host) {
        detect_listen_address(trunk, target_host);
    }

    /* Resolve target once, store in trunk_state */
    int target_af = AF_INET;
    if (target_host) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(target_host, "5060", &hints, &res) == 0 && res) {
            target_af = res->ai_family;
            trunk->target_addrlen = res->ai_addrlen;
            memcpy(&trunk->target_addr, res->ai_addr, res->ai_addrlen);
            /* Override port to target's configured port */
            int port = config->target->port ? atoi(config->target->port) : 5060;
            if (target_af == AF_INET) {
                ((struct sockaddr_in *)&trunk->target_addr)->sin_port = htons(port);
            } else {
                ((struct sockaddr_in6 *)&trunk->target_addr)->sin6_port = htons(port);
            }
            freeaddrinfo(res);
        }
    }
    trunk->target_af = target_af;

    /* Create SIP socket matching target's address family — no bind */
    int sip_fd = socket(target_af, SOCK_DGRAM, 0);
    if (sip_fd < 0) {
        fprintf(stderr, "daemon: failed to create SIP UDP socket\n");
        return 1;
    }
    int flags = fcntl(sip_fd, F_GETFL, 0);
    fcntl(sip_fd, F_SETFL, flags | O_NONBLOCK);

    /* Store as {1, fd} fd array for sched_has_data */
    int *sip_fds = malloc(2 * sizeof(int));
    sip_fds[0] = 1;
    sip_fds[1] = sip_fd;
    trunk->sip_fds = sip_fds;

    /* Start SIP receive task (handles registration + signalling) */
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

    printf("UPBX trunk running. Press Ctrl+C to stop.\n");
    fflush(stdout);

    sched_main();

    if (backbone) backbone_free(backbone);
    trunk_free(trunk);
    close(sip_fd);
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
