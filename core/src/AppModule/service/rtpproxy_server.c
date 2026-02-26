/*
 * RTP Proxy: handles both UDP and TCP RTP forwarding.
 *
 * All media passes through the PBX RTP proxy; no direct peer-to-peer RTP.
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

#define MAX_CALLS 256

typedef struct {
  int forward_sock;
  int tcp_listen_sock;
  int tcp_conn_sock;
  struct sockaddr_in remote;
  char transport[4];
  int in_use;
} rtp_call_t;

static rtp_call_t calls[MAX_CALLS];
static int rtp_initialized;

void rtpproxy_init(void) {
  if (rtp_initialized) return;
  memset(calls, 0, sizeof(calls));
  rtp_initialized = 1;
}

void rtpproxy_cleanup(void) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (calls[i].forward_sock > 0) close(calls[i].forward_sock);
    if (calls[i].tcp_listen_sock > 0) close(calls[i].tcp_listen_sock);
    if (calls[i].tcp_conn_sock > 0) close(calls[i].tcp_conn_sock);
  }
  memset(calls, 0, sizeof(calls));
  rtp_initialized = 0;
}

int rtpproxy_alloc_udp_port(struct in_addr local_ip, int port_low, int port_high,
                             int *sock, int *port) {
  for (int p = port_low; p <= port_high; p += 2) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) continue;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = local_ip;
    addr.sin_port = htons((uint16_t)p);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      *sock = s;
      *port = p;
      return 0;
    }
    close(s);
  }
  return -1;
}

int rtpproxy_alloc_tcp_port(struct in_addr local_ip, int port_low, int port_high,
                           int *sock, int *port) {
  for (int p = port_low; p <= port_high; p += 2) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) continue;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = local_ip;
    addr.sin_port = htons((uint16_t)p);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      if (listen(s, 1) == 0) {
        *sock = s;
        *port = p;
        return 0;
      }
    }
    close(s);
  }
  return -1;
}

int rtpproxy_connect_tcp(const char *remote_ip, int remote_port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)remote_port);

  if (inet_pton(AF_INET, remote_ip, &addr.sin_addr) <= 0) {
    struct hostent *he = gethostbyname(remote_ip);
    if (!he) return -1;
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
  }

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return -1;

  int flags = fcntl(s, F_GETFL, 0);
  fcntl(s, F_SETFL, flags | O_NONBLOCK);

  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS) {
    close(s);
    return -1;
  }

  return s;
}

void rtpproxy_register_call(int forward_sock, int tcp_listen_sock, int tcp_conn_sock,
                            struct sockaddr_in *remote, const char *transport) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (!calls[i].in_use) {
      calls[i].in_use = 1;
      calls[i].forward_sock = forward_sock;
      calls[i].tcp_listen_sock = tcp_listen_sock;
      calls[i].tcp_conn_sock = tcp_conn_sock;
      if (remote) memcpy(&calls[i].remote, remote, sizeof(*remote));
      if (transport) {
        memcpy(calls[i].transport, transport, 4);
      } else {
        memcpy(calls[i].transport, "udp", 4);
      }
      return;
    }
  }
  log_error("rtpproxy: no free slots for new call");
}

void rtpproxy_unregister_call(int forward_sock, int tcp_listen_sock, int tcp_conn_sock) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (calls[i].in_use &&
        calls[i].forward_sock == forward_sock &&
        calls[i].tcp_listen_sock == tcp_listen_sock &&
        calls[i].tcp_conn_sock == tcp_conn_sock) {
      calls[i].in_use = 0;
      if (calls[i].forward_sock > 0) close(calls[i].forward_sock);
      if (calls[i].tcp_listen_sock > 0) close(calls[i].tcp_listen_sock);
      if (calls[i].tcp_conn_sock > 0) close(calls[i].tcp_conn_sock);
      calls[i].forward_sock = 0;
      calls[i].tcp_listen_sock = 0;
      calls[i].tcp_conn_sock = 0;
      return;
    }
  }
}

void rtpproxy_fill_fds(fd_set *read_set, int *maxfd) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (!calls[i].in_use) continue;
    if (calls[i].forward_sock > 0) {
      FD_SET(calls[i].forward_sock, read_set);
      if (calls[i].forward_sock > *maxfd) *maxfd = calls[i].forward_sock;
    }
    if (calls[i].tcp_listen_sock > 0) {
      FD_SET(calls[i].tcp_listen_sock, read_set);
      if (calls[i].tcp_listen_sock > *maxfd) *maxfd = calls[i].tcp_listen_sock;
    }
    if (calls[i].tcp_conn_sock > 0) {
      FD_SET(calls[i].tcp_conn_sock, read_set);
      if (calls[i].tcp_conn_sock > *maxfd) *maxfd = calls[i].tcp_conn_sock;
    }
  }
}

void rtpproxy_process(fd_set *read_set,
                      int forward_sock_a, int tcp_listen_a, int tcp_conn_a, struct sockaddr_in *remote_a,
                      int forward_sock_b, int tcp_listen_b, int tcp_conn_b, struct sockaddr_in *remote_b,
                      time_t *active_at, unsigned long *pkts_a2b, unsigned long *pkts_b2a) {
  char buf[RTP_BUF_SIZE];
  ssize_t n;

  if (forward_sock_a > 0 && FD_ISSET(forward_sock_a, read_set)) {
    n = recv(forward_sock_a, buf, sizeof(buf), 0);
    if (n > 0 && remote_b) {
      sendto(forward_sock_b, buf, n, 0, (struct sockaddr *)remote_b, sizeof(*remote_b));
      if (active_at) *active_at = time(NULL);
      if (pkts_a2b) (*pkts_a2b)++;
    }
  }

  if (forward_sock_b > 0 && FD_ISSET(forward_sock_b, read_set)) {
    n = recv(forward_sock_b, buf, sizeof(buf), 0);
    if (n > 0 && remote_a) {
      sendto(forward_sock_a, buf, n, 0, (struct sockaddr *)remote_a, sizeof(*remote_a));
      if (active_at) *active_at = time(NULL);
      if (pkts_b2a) (*pkts_b2a)++;
    }
  }

  if (tcp_listen_a > 0 && FD_ISSET(tcp_listen_a, read_set)) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(tcp_listen_a, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd > 0) {
      log_trace("rtpproxy: accepted TCP connection on listen_a");
    }
  }

  if (tcp_listen_b > 0 && FD_ISSET(tcp_listen_b, read_set)) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(tcp_listen_b, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd > 0) {
      log_trace("rtpproxy: accepted TCP connection on listen_b");
    }
  }

  if (tcp_conn_a > 0 && FD_ISSET(tcp_conn_a, read_set)) {
    n = recv(tcp_conn_a, buf, sizeof(buf), 0);
    if (n > 0 && forward_sock_b > 0 && remote_b) {
      sendto(forward_sock_b, buf, n, 0, (struct sockaddr *)remote_b, sizeof(*remote_b));
      if (active_at) *active_at = time(NULL);
      if (pkts_a2b) (*pkts_a2b)++;
    }
  }

  if (tcp_conn_b > 0 && FD_ISSET(tcp_conn_b, read_set)) {
    n = recv(tcp_conn_b, buf, sizeof(buf), 0);
    if (n > 0 && forward_sock_a > 0 && remote_a) {
      sendto(forward_sock_a, buf, n, 0, (struct sockaddr *)remote_a, sizeof(*remote_a));
      if (active_at) *active_at = time(NULL);
      if (pkts_b2a) (*pkts_b2a)++;
    }
  }
}


/* RTPP Server implementation */
static char *rtpproxy_server_url = NULL;
static int rtpproxy_server_port_low = 10000;
static int rtpproxy_server_port_high = 20000;
static int rtpproxy_server_sockfd = -1;
static int rtpproxy_server_running = 0;

#define MAX_SESSIONS 256

typedef struct {
  char call_id[128];
  char from_tag[64];
  char to_tag[64];
  int port;
  int sockfd;
  struct sockaddr_in remote;
  int active;
} rtpp_session_t;

static rtpp_session_t sessions[MAX_SESSIONS];
static int session_count = 0;
static int next_port = 0;

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
      if (sessions[i].active && sessions[i].port == p) {
        in_use = 1;
        break;
      }
    }
    if (!in_use) {
      next_port = p;
      return p;
    }
  }
  return -1;
}

static rtpp_session_t *find_session(const char *call_id, const char *from_tag) {
  for (int i = 0; i < session_count; i++) {
    if (sessions[i].active &&
        strcmp(sessions[i].call_id, call_id) == 0 &&
        strcmp(sessions[i].from_tag, from_tag) == 0) {
      return &sessions[i];
    }
  }
  return NULL;
}

static rtpp_session_t *add_session_full(const char *call_id, const char *from_tag, const char *to_tag,
                                         const char *remote_ip, int remote_port) {
  rtpp_session_t *s = find_session(call_id, from_tag);
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
      size_t call_id_len = strlen(call_id);
      if (call_id_len >= sizeof(sessions[i].call_id)) call_id_len = sizeof(sessions[i].call_id) - 1;
      memcpy(sessions[i].call_id, call_id, call_id_len);
      sessions[i].call_id[call_id_len] = '\0';
      size_t from_tag_len = strlen(from_tag);
      if (from_tag_len >= sizeof(sessions[i].from_tag)) from_tag_len = sizeof(sessions[i].from_tag) - 1;
      memcpy(sessions[i].from_tag, from_tag, from_tag_len);
      sessions[i].from_tag[from_tag_len] = '\0';
      if (to_tag) {
        size_t to_tag_len = strlen(to_tag);
        if (to_tag_len >= sizeof(sessions[i].to_tag)) to_tag_len = sizeof(sessions[i].to_tag) - 1;
        memcpy(sessions[i].to_tag, to_tag, to_tag_len);
        sessions[i].to_tag[to_tag_len] = '\0';
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
      log_trace("rtpproxy: created session %s:%d -> %s:%d (local port %d)", 
                from_tag, port, remote_ip ? remote_ip : "none", remote_port, port);
      return &sessions[i];
    }
  }
  close(sockfd);
  return NULL;
}

static void remove_session(const char *call_id, const char *from_tag) {
  rtpp_session_t *s = find_session(call_id, from_tag);
  if (s) {
    if (s->sockfd >= 0) {
      close(s->sockfd);
      s->sockfd = -1;
    }
    s->active = 0;
    s->port = 0;
    log_trace("rtpproxy: removed session %s", from_tag);
  }
}

void rtpproxy_server_set_config(const char *url, int port_low, int port_high) {
  free(rtpproxy_server_url);
  rtpproxy_server_url = url ? strdup(url) : NULL;
  rtpproxy_server_port_low = port_low;
  rtpproxy_server_port_high = port_high;
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

int rtpproxy_server_init(void) {
  if (!rtpproxy_server_url) { log_error("rtpproxy: no URL configured"); return -1; }
  if (create_server_socket(rtpproxy_server_url, &rtpproxy_server_sockfd) < 0) {
    log_error("rtpproxy: failed to create server socket for %s", rtpproxy_server_url);
    return -1;
  }
  rtpproxy_server_running = 1;
  log_info("rtpproxy: listening on %s", rtpproxy_server_url);
  return 0;
}

void rtpproxy_server_shutdown(void) {
  rtpproxy_server_running = 0;
  if (rtpproxy_server_sockfd >= 0) { close(rtpproxy_server_sockfd); rtpproxy_server_sockfd = -1; }
  if (rtpproxy_server_url && strncmp(rtpproxy_server_url, "unix://", 7) == 0) unlink(rtpproxy_server_url + 7);
  else if (rtpproxy_server_url && strncmp(rtpproxy_server_url, "cunix://", 8) == 0) unlink(rtpproxy_server_url + 8);
  log_info("rtpproxy: server shutdown");
}

static struct pt rtpproxy_init_pt;

static PT_THREAD(rtpproxy_init_fn(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp; (void)task;
  PT_BEGIN(pt);

  PT_WAIT_UNTIL(pt, config_get_path() != NULL);

  static const char default_url[] = "unix:///var/run/upbx-rtpproxy.sock";

  resp_object *mode_obj = config_key_get("rtpproxy", "mode");
  char *mode = NULL;
  if (mode_obj && (mode_obj->type == RESPT_BULK || mode_obj->type == RESPT_SIMPLE) && mode_obj->u.s) {
    mode = mode_obj->u.s;
  }

  /* Default to builtin if not specified */
  int is_builtin = (mode && strcmp(mode, "builtin") == 0) || mode == NULL;
  char *url = NULL;

  if (is_builtin) {
    resp_object *url_obj = config_key_get("rtpproxy", "url");
    if (url_obj && (url_obj->type == RESPT_BULK || url_obj->type == RESPT_SIMPLE) && url_obj->u.s && url_obj->u.s[0]) {
      url = strdup(url_obj->u.s);
      resp_free(url_obj);
    } else {
      url = (char *)default_url;
      if (url_obj) { resp_free(url_obj); url_obj = NULL; }
    }

    resp_object *ports_obj = config_key_get("rtpproxy", "ports");
    int port_low = 10000;
    int port_high = 20000;
    if (ports_obj && ports_obj->type == RESPT_BULK && ports_obj->u.s) {
      sscanf(ports_obj->u.s, "%d-%d", &port_low, &port_high);
    }
    if (ports_obj) resp_free(ports_obj);

    rtpproxy_server_set_config(url, port_low, port_high);

    if (rtpproxy_server_init() < 0) {
      /* Check if it's EADDRINUSE - then fallback to external */
      if (errno == EADDRINUSE) {
        log_warn("rtpproxy: socket in use, falling back to external mode");
        is_builtin = 0;
      } else {
        log_fatal("rtpproxy: FAILED TO START - FATAL: media would bypass rtpproxy, system unsafe to run");
        _exit(1);
      }
    }
  }

  if (!is_builtin) {
    /* External mode - initialize client */
    if (rtpproxy_client_global_init() < 0) {
      log_fatal("rtpproxy: external rtpproxy unavailable - FATAL: media would bypass rtpproxy, system unsafe to run");
      _exit(1);
    }
    
    /* Verify connection works by sending version command */
    char version[32] = {0};
    if (rtpp_version(rtpproxy_get_client(), version, sizeof(version)) < 0) {
      log_fatal("rtpproxy: external rtpproxy not responding - FATAL: media would bypass rtpproxy, system unsafe to run");
      _exit(1);
    }
    log_info("rtpproxy: connected to external (version: %s)", version);
  }

  if (mode_obj) resp_free(mode_obj);
  if (url && url != default_url) free(url);

  PT_END(pt);
}

static struct pt rtpproxy_cmd_pt;

static PT_THREAD(rtpproxy_cmd_fn(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp;
  PT_BEGIN(pt);

  for (;;) {
    PT_WAIT_UNTIL(pt, rtpproxy_server_sockfd >= 0 && rtpproxy_server_running);

    task->read_fds = &rtpproxy_server_sockfd;
    task->read_fds_count = 1;

    PT_YIELD_UNTIL(pt, rtpproxy_server_sockfd >= 0 && 
                     pt_task_has_data(task, &rtpproxy_server_sockfd) == 0);

    if (!rtpproxy_server_running || rtpproxy_server_sockfd < 0) continue;

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
      char call_id[128] = {0}, from_tag[64] = {0};
      char remote_ip[64] = {0};
      int remote_port = 0;
      sscanf(cmd + 1, "%s %s %d %s", call_id, remote_ip, &remote_port, from_tag);
      if (call_id[0] && from_tag[0] && remote_port > 0) {
        rtpp_session_t *s = add_session_full(call_id, from_tag, NULL, remote_ip, remote_port);
        if (s) {
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
          log_trace("rtpproxy: U %s %s -> port %d %s", call_id, from_tag, s->port, local_ip);
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
      rtpp_session_t *s = find_session(call_id, from_tag);
      if (s) snprintf(reply, sizeof(reply), "%d\n", s->port);
      else snprintf(reply, sizeof(reply), "ECODE_SESUNKN\n");
    } else if (cmd[0] == 'D') {
      char call_id[128] = {0}, from_tag[64] = {0};
      sscanf(cmd + 1, "%s %s", call_id, from_tag);
      if (call_id[0] && from_tag[0]) {
        remove_session(call_id, from_tag);
        snprintf(reply, sizeof(reply), "0\n");
        log_trace("rtpproxy: D %s %s", call_id, from_tag);
      } else {
        snprintf(reply, sizeof(reply), "ECODE_PARSE_NARGS\n");
      }
    } else if (cmd[0] == 'Q') {
      char call_id[128] = {0}, from_tag[64] = {0};
      sscanf(cmd + 1, "%s %s", call_id, from_tag);
      rtpp_session_t *s = find_session(call_id, from_tag);
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

static struct pt rtpproxy_media_pt;

#define RTP_MEDIA_BUF_SIZE 1520

static PT_THREAD(rtpproxy_media_fn(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp;
  static char buf[RTP_MEDIA_BUF_SIZE];
  
  PT_BEGIN(pt);

  for (;;) {
    PT_YIELD(pt);

    if (!rtpproxy_server_running) continue;

    for (int i = 0; i < session_count; i++) {
      if (!sessions[i].active || sessions[i].sockfd < 0) continue;
      if (sessions[i].remote.sin_port == 0) continue;

      task->read_fds = &sessions[i].sockfd;
      task->read_fds_count = 1;

      if (pt_task_has_data(task, &sessions[i].sockfd) == 0 && sessions[i].sockfd >= 0) {
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(sessions[i].sockfd, buf, sizeof(buf), 0, 
                             (struct sockaddr *)&from, &fromlen);
        if (n > 0) {
          sendto(sessions[i].sockfd, buf, n, 0, 
                 (struct sockaddr *)&sessions[i].remote, sizeof(sessions[i].remote));
          log_trace("rtpproxy: forwarded %zd bytes from port %d to %s:%d", 
                    n, sessions[i].port,
                    inet_ntoa(sessions[i].remote.sin_addr),
                    ntohs(sessions[i].remote.sin_port));
        }
      }
    }
  }

  PT_END(pt);
}

static void __attribute__((constructor)) rtpproxy_register(void) {
  PT_INIT(&rtpproxy_init_pt);
  appmodule_pt_add(rtpproxy_init_fn, NULL);
  PT_INIT(&rtpproxy_cmd_pt);
  appmodule_pt_add(rtpproxy_cmd_fn, NULL);
  PT_INIT(&rtpproxy_media_pt);
  appmodule_pt_add(rtpproxy_media_fn, NULL);
}
