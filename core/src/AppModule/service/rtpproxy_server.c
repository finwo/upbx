/*
 * Built-in RTP proxy - uses PBX scheduler (protothreads).
 *
 * Runs when mode=builtin, registers as appmodule via constructor.
 * - rtpproxy_listener_pt: listens on control socket, handles commands
 * - rtpproxy_session_pt: relays RTP for one session (spawned per session)
 *
 * PBX communicates via control protocol only - no RTP relay in PBX.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "rxi/log.h"
#include "config.h"
#include "RespModule/resp.h"
#include "AppModule/service/rtpproxy.h"
#include "AppModule/util/rtpproxy_client.h"
#include "common/pt.h"
#include "AppModule/command/daemon.h"

#define MAX_SESSIONS 256
#define RTP_MEDIA_BUF_SIZE 1520

typedef struct rtp_session {
  char call_id[128];
  char from_tag[64];
  char to_tag[64];
  int port;
  int sockfd;
  struct sockaddr_in remote;
  int active;
  struct pt pt;
} rtp_session_t;

static rtp_session_t sessions[MAX_SESSIONS];
static int session_count = 0;
static int next_port = 0;
static int rtpproxy_server_port_low = 10000;
static int rtpproxy_server_port_high = 20000;

static int rtpproxy_server_sockfd = -1;
static int rtpproxy_server_running = 0;

/* Forward declarations */
static int alloc_session_port(void);
static rtp_session_t *find_session(const char *call_id, const char *from_tag);
static rtp_session_t *add_session_full(const char *call_id, const char *from_tag, const char *to_tag,
                                        const char *remote_ip, int remote_port);
static void remove_session(const char *call_id, const char *from_tag);
static int create_server_socket(const char *url, int *out_sock);

/* Session RTP relay protothread - one per session */
static PT_THREAD(rtpproxy_session_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp;
  static char buf[RTP_MEDIA_BUF_SIZE];
  rtp_session_t *session = task->udata;

  PT_BEGIN(pt);

  if (!session || !session->active || session->sockfd < 0) {
    PT_EXIT(pt);
  }

  for (;;) {
    task->read_fds = &session->sockfd;
    task->read_fds_count = 1;

    PT_YIELD(pt);

    if (!session || !session->active || session->sockfd < 0) {
      break;
    }

    if (session->remote.sin_port == 0) {
      continue;
    }

    int ready_fd = -1;
    if (pt_task_has_data(task, &ready_fd) != 0 || ready_fd != session->sockfd) {
      continue;
    }

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(session->sockfd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &fromlen);
    if (n > 0) {
      sendto(session->sockfd, buf, n, 0,
             (struct sockaddr *)&session->remote, sizeof(session->remote));
      log_trace("rtpproxy: forwarded %zd bytes from port %d to %s:%d",
                n, session->port,
                inet_ntoa(session->remote.sin_addr),
                ntohs(session->remote.sin_port));
    }
  }

  PT_END(pt);
}

/* Control command handler - listens on control socket */
static PT_THREAD(rtpproxy_listener_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp;
  PT_BEGIN(pt);

  for (;;) {
    PT_WAIT_UNTIL(pt, rtpproxy_server_sockfd >= 0 && rtpproxy_server_running);

    task->read_fds = &rtpproxy_server_sockfd;
    task->read_fds_count = 1;

    PT_YIELD(pt);

    if (!rtpproxy_server_running || rtpproxy_server_sockfd < 0) continue;

    int ready_fd = -1;
    if (pt_task_has_data(task, &ready_fd) != 0 || ready_fd != rtpproxy_server_sockfd) continue;

    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(rtpproxy_server_sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) continue;

    char cmd_buf[512] = {0};
    ssize_t cmd_len = recv(client_fd, cmd_buf, sizeof(cmd_buf) - 1, 0);
    if (cmd_len <= 0) { close(client_fd); continue; }
    cmd_buf[cmd_len] = '\0';

    char *cmd = cmd_buf;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    char *end = cmd + strlen(cmd) - 1;
    while (end > cmd && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) *end-- = '\0';

    char reply[256] = {0};

    if (cmd[0] == 'V' && (cmd[1] == '\0' || cmd[1] == ' ' || cmd[1] == '\t')) {
      snprintf(reply, sizeof(reply), "20040107\n");
    } else if (cmd[0] == 'U') {
      char call_id[128] = {0}, from_tag[64] = {0}, to_tag[64] = {0};
      char remote_ip[64] = {0};
      int remote_port = 0;
      int parsed = sscanf(cmd + 1, "%s %s %d %s %s", call_id, remote_ip, &remote_port, from_tag, to_tag);
      if (parsed >= 4 && call_id[0] && from_tag[0] && remote_port > 0) {
        rtp_session_t *s = add_session_full(call_id, from_tag, to_tag[0] ? to_tag : NULL, remote_ip, remote_port);
        if (s) {
          /* Spawn per-session protothread */
          PT_INIT(&s->pt);
          appmodule_pt_add(rtpproxy_session_pt, s);

          char local_ip[64] = {0};
          struct sockaddr_in local_addr;
          socklen_t addr_len = sizeof(local_addr);
          if (getsockname(s->sockfd, (struct sockaddr *)&local_addr, &addr_len) == 0) {
            inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));
          }
          if (local_ip[0]) {
            snprintf(reply, sizeof(reply), "%d %s\n", s->port, local_ip);
          } else {
            snprintf(reply, sizeof(reply), "%d\n", s->port);
          }
          log_trace("rtpproxy: U %s %s -> port %d %s (session pt spawned)", call_id, from_tag, s->port, local_ip);
        } else {
          snprintf(reply, sizeof(reply), "ECODE_NOMEM_1\n");
        }
      } else {
        snprintf(reply, sizeof(reply), "ECODE_PARSE_NARGS\n");
      }
    } else if (cmd[0] == 'L') {
      char call_id[128] = {0}, from_tag[64] = {0};
      char remote_ip[64] = {0};
      int remote_port = 0;
      sscanf(cmd + 1, "%s %s %d %s", call_id, remote_ip, &remote_port, from_tag);
      rtp_session_t *s = find_session(call_id, from_tag);
      if (s) snprintf(reply, sizeof(reply), "%d\n", s->port);
      else snprintf(reply, sizeof(reply), "ECODE_SESUNKN\n");
    } else if (cmd[0] == 'D') {
      char call_id[128] = {0}, from_tag[64] = {0};
      sscanf(cmd + 1, "%s %s", call_id, from_tag);
      if (call_id[0] && from_tag[0]) {
        /* Session pt will exit when it sees active=0 */
        remove_session(call_id, from_tag);
        snprintf(reply, sizeof(reply), "0\n");
        log_trace("rtpproxy: D %s %s (session will terminate)", call_id, from_tag);
      } else {
        snprintf(reply, sizeof(reply), "ECODE_PARSE_NARGS\n");
      }
    } else if (cmd[0] == 'Q') {
      char call_id[128] = {0}, from_tag[64] = {0};
      sscanf(cmd + 1, "%s %s", call_id, from_tag);
      rtp_session_t *s = find_session(call_id, from_tag);
      if (s) snprintf(reply, sizeof(reply), "ttl=60\n");
      else snprintf(reply, sizeof(reply), "ECODE_SESUNKN\n");
    } else {
      snprintf(reply, sizeof(reply), "ECODE_CMDUNKN\n");
    }

    if (reply[0]) send(client_fd, reply, strlen(reply), 0);
    close(client_fd);
  }

  PT_END(pt);
}

/* Init function - checks config, starts builtin if needed */
static struct pt rtpproxy_init_pt;

static PT_THREAD(rtpproxy_init_fn(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp; (void)task;
  PT_BEGIN(pt);

  PT_WAIT_UNTIL(pt, global_cfg != NULL);

  const char *mode = global_cfg->rtpproxy.mode;
  int is_builtin = (mode && strcmp(mode, "builtin") == 0);

  if (!is_builtin) {
    /* External mode - initialize client only */
    if (rtpproxy_client_global_init() < 0) {
      log_fatal("rtpproxy: external rtpproxy unavailable - FATAL");
      _exit(1);
    }
    char version[32] = {0};
    if (rtpp_version(rtpproxy_get_client(), version, sizeof(version)) < 0) {
      log_fatal("rtpproxy: external rtpproxy not responding - FATAL");
      _exit(1);
    }
    log_info("rtpproxy: connected to external (version: %s)", version);
    PT_EXIT(pt);
  }

  /* Builtin mode */
  const char *url = global_cfg->rtpproxy.url;
  if (!url || !url[0]) {
    url = "unix:///var/run/upbx-rtpproxy.sock";
  }

  rtpproxy_server_port_low = global_cfg->rtpproxy.port_low;
  rtpproxy_server_port_high = global_cfg->rtpproxy.port_high;

  if (create_server_socket(url, &rtpproxy_server_sockfd) < 0) {
    if (errno == EADDRINUSE) {
      log_warn("rtpproxy: socket in use, falling back to external mode");
      if (rtpproxy_client_global_init() < 0) {
        log_fatal("rtpproxy: no rtpproxy available - FATAL");
        _exit(1);
      }
      PT_EXIT(pt);
    }
    log_fatal("rtpproxy: failed to create server socket for %s - FATAL", url);
    _exit(1);
  }

  rtpproxy_server_running = 1;
  log_info("rtpproxy: builtin listening on %s", url);

  PT_END(pt);
}

/* Helper functions */

static int alloc_session_port(void) {
  int range = rtpproxy_server_port_high - rtpproxy_server_port_low + 1;
  if (range <= 0) return -1;

  if (next_port < rtpproxy_server_port_low || next_port > rtpproxy_server_port_high)
    next_port = rtpproxy_server_port_high;

  for (int k = 0; k < range; k++) {
    int p = (next_port - rtpproxy_server_port_low + 2 + k) % range + rtpproxy_server_port_low;
    p &= ~1;
    if (p < rtpproxy_server_port_low) p += 2;

    int in_use = 0;
    for (int i = 0; i < session_count; i++) {
      if (sessions[i].active && sessions[i].port == p) { in_use = 1; break; }
    }
    if (!in_use) { next_port = p; return p; }
  }
  return -1;
}

static rtp_session_t *find_session(const char *call_id, const char *from_tag) {
  for (int i = 0; i < session_count; i++) {
    if (sessions[i].active &&
        strcmp(sessions[i].call_id, call_id) == 0 &&
        strcmp(sessions[i].from_tag, from_tag) == 0) {
      return &sessions[i];
    }
  }
  return NULL;
}

static rtp_session_t *add_session_full(const char *call_id, const char *from_tag, const char *to_tag,
                                       const char *remote_ip, int remote_port) {
  rtp_session_t *s = find_session(call_id, from_tag);
  if (s) return s;

  int port = alloc_session_port();
  if (port <= 0) return NULL;

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd < 0) return NULL;

  struct sockaddr_in local_addr = {0};
  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons((uint16_t)port);
  local_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
    close(sockfd);
    return NULL;
  }

  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (!sessions[i].active) {
      sessions[i].active = 1;
      sessions[i].sockfd = sockfd;
      sessions[i].port = port;

      size_t n = strlen(call_id);
      if (n >= sizeof(sessions[i].call_id)) n = sizeof(sessions[i].call_id) - 1;
      memcpy(sessions[i].call_id, call_id, n);
      sessions[i].call_id[n] = '\0';

      n = strlen(from_tag);
      if (n >= sizeof(sessions[i].from_tag)) n = sizeof(sessions[i].from_tag) - 1;
      memcpy(sessions[i].from_tag, from_tag, n);
      sessions[i].from_tag[n] = '\0';

      if (to_tag) {
        n = strlen(to_tag);
        if (n >= sizeof(sessions[i].to_tag)) n = sizeof(sessions[i].to_tag) - 1;
        memcpy(sessions[i].to_tag, to_tag, n);
        sessions[i].to_tag[n] = '\0';
      } else {
        sessions[i].to_tag[0] = '\0';
      }

      memset(&sessions[i].remote, 0, sizeof(sessions[i].remote));
      if (remote_ip && remote_port > 0) {
        sessions[i].remote.sin_family = AF_INET;
        sessions[i].remote.sin_port = htons((uint16_t)remote_port);
        inet_pton(AF_INET, remote_ip, &sessions[i].remote.sin_addr);
      }

      if (session_count < i + 1) session_count = i + 1;
      return &sessions[i];
    }
  }
  close(sockfd);
  return NULL;
}

static void remove_session(const char *call_id, const char *from_tag) {
  rtp_session_t *s = find_session(call_id, from_tag);
  if (s) {
    s->active = 0;
    if (s->sockfd >= 0) { close(s->sockfd); s->sockfd = -1; }
    log_trace("rtpproxy: removed session %s", from_tag);
  }
}

static int create_server_socket(const char *url, int *out_sock) {
  if (!url || !out_sock) return -1;
  *out_sock = -1;

  if (strncmp(url, "unix://", 7) == 0) {
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, url + 7, sizeof(addr.sun_path) - 1);
    unlink(addr.sun_path);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    *out_sock = sock;
    return 0;
  }

  if (strncmp(url, "cunix://", 8) == 0) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, url + 8, sizeof(addr.sun_path) - 1);
    unlink(addr.sun_path);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    if (listen(sock, 5) < 0) { close(sock); return -1; }
    *out_sock = sock;
    return 0;
  }

  if (strncmp(url, "tcp://", 6) == 0) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    const char *hp = url + 6;
    const char *colon = strchr(hp, ':');
    char *host = NULL;
    int port = 22222;
    if (colon) { host = strndup(hp, colon - hp); port = atoi(colon + 1); if (port == 0) port = 22222; }
    else { host = strdup(hp); }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) addr.sin_addr.s_addr = INADDR_ANY;
    else inet_pton(AF_INET, host, &addr.sin_addr);
    free(host);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    if (listen(sock, 5) < 0) { close(sock); return -1; }
    *out_sock = sock;
    return 0;
  }

  if (strncmp(url, "udp://", 6) == 0) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    const char *hp = url + 6;
    const char *colon = strchr(hp, ':');
    char *host = NULL;
    int port = 22222;
    if (colon) { host = strndup(hp, colon - hp); port = atoi(colon + 1); if (port == 0) port = 22222; }
    else { host = strdup(hp); }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (strcmp(host, "*") == 0 || strcmp(host, "0.0.0.0") == 0) addr.sin_addr.s_addr = INADDR_ANY;
    else inet_pton(AF_INET, host, &addr.sin_addr);
    free(host);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    *out_sock = sock;
    return 0;
  }

  return -1;
}

/* Register as appmodule - scheduler runs these protothreads */
static void __attribute__((constructor)) rtpproxy_register(void) {
  PT_INIT(&rtpproxy_init_pt);
  appmodule_pt_add(rtpproxy_init_fn, NULL);

  /* These start after init completes and rtpproxy_server_running is set */
  appmodule_pt_add(rtpproxy_listener_pt, NULL);
}
