#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "SchedulerModule/protothreads.h"
#include "SchedulerModule/scheduler.h"
#include "common/socket_util.h"
#include "config.h"
#include "tidwall/hashmap.h"
#include "server.h"

#define RTP_SESSION_HASH_SIZE 256
#define RTP_BUFFER_SIZE 4096

typedef struct rtp_session {
  char *call_id;
  char *from_tag;
  char *to_tag;

  int *leg_a_fds;
  int leg_a_local_port;
  int leg_a_connected;
  struct sockaddr_storage leg_a_remote_addr;
  socklen_t leg_a_remote_addrlen;

  int *leg_b_fds;
  int leg_b_local_port;
  int leg_b_connect_mode;
  struct sockaddr_storage leg_b_remote_addr;
  socklen_t leg_b_remote_addrlen;

  time_t created;
  time_t last_activity;
  int marked_for_deletion;
} rtp_session_t;

static int *create_leg_socket(int local_port);
static int parse_ip_addr(const char *ip_str, int port, struct sockaddr_storage *addr, socklen_t *addrlen);
static int connect_to_remote(struct sockaddr_storage *addr, socklen_t addrlen);
static void spawn_session_pt(rtp_session_t *s);

static struct hashmap *sessions = NULL;
static int *server_sockfds = NULL;
static char *advertise_addr = NULL;
static int port_low = 10000;
static int port_high = 20000;
static int port_cur = 10000;
static char *control_address = NULL;

static uint64_t session_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  const rtp_session_t *s = item;
  return hashmap_sip(s->call_id, strlen(s->call_id), seed0, seed1);
}

static int session_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  const rtp_session_t *sa = a;
  const rtp_session_t *sb = b;
  return strcmp(sa->call_id, sb->call_id);
}

static const rtp_session_t *find_session(const char *call_id) {
  if (!sessions || !call_id) return NULL;
  rtp_session_t key = { .call_id = (char *)call_id };
  return hashmap_get(sessions, &key);
}

static void close_leg_fds(int *fds) {
  if (!fds) return;
  for (int i = 1; i <= fds[0]; i++) {
    if (fds[i] >= 0) close(fds[i]);
  }
  free(fds);
}

static void remove_session(rtp_session_t *s) {
  close_leg_fds(s->leg_a_fds);
  close_leg_fds(s->leg_b_fds);
  free(s->call_id);
  free(s->from_tag);
  free(s->to_tag);
  free(s);
}

static void destroy_session(rtp_session_t *s) {
  if (sessions) {
    hashmap_delete(sessions, s);
  }
  remove_session(s);
}

static int alloc_port_pair(void) {
  for (int i = 0; i < port_high - port_low; i++) {
    int port = port_cur + i;
    if (port > port_high) port = port_low;
    port_cur = port + 2;
    if (port_cur > port_high) port_cur = port_low;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) continue;
    int udp_ok = (bind(udp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    close(udp_fd);
    if (!udp_ok) continue;

    return port;
  }
  return 0;
}

static int *create_leg_socket(int local_port) {
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", local_port);
  return udp_recv(port_str, NULL, NULL);
}

static int parse_ip_addr(const char *ip_str, int port, struct sockaddr_storage *addr, socklen_t *addrlen) {
  memset(addr, 0, sizeof(*addr));

  struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
  if (inet_pton(AF_INET, ip_str, &addr4->sin_addr) == 1) {
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    *addrlen = sizeof(*addr4);
    return 0;
  }

  struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
  if (inet_pton(AF_INET6, ip_str, &addr6->sin6_addr) == 1) {
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);
    *addrlen = sizeof(*addr6);
    return 0;
  }

  return -1;
}

static int connect_to_remote(struct sockaddr_storage *addr, socklen_t addrlen) {
  int fd = socket(addr->ss_family, SOCK_DGRAM, 0);
  if (fd < 0) return -1;

  set_socket_nonblocking(fd, 1);

  return fd;
}

static rtp_session_t *create_session(const char *call_id, const char *from_tag) {
  const rtp_session_t *cs = find_session(call_id);
  if (cs) return (rtp_session_t *)cs;

  int port = alloc_port_pair();
  if (!port) {
    log_error("rtpproxy: no ports available");
    return NULL;
  }

  rtp_session_t *s = calloc(1, sizeof(*s));
  if (!s) return NULL;

  s->call_id = strdup(call_id);
  s->from_tag = strdup(from_tag);
  s->leg_a_fds = NULL;
  s->leg_b_fds = NULL;
  s->created = time(NULL);
  s->last_activity = s->created;

  if (!sessions) {
    sessions = hashmap_new(sizeof(rtp_session_t), 0, 0, 0, session_hash, session_compare, NULL, NULL);
  }
  hashmap_set(sessions, s);

  log_debug("rtpproxy: created session %s/%s port %d", call_id, from_tag, port);
  return s;
}

static int delete_session(const char *call_id, const char *from_tag, const char *to_tag) {
  const rtp_session_t *cs = find_session(call_id);
  if (!cs) return -1;

  if (from_tag && strcmp(cs->from_tag, from_tag) != 0) {
    return -1;
  }
  if (to_tag && cs->to_tag && strcmp(cs->to_tag, to_tag) != 0) {
    return -1;
  }

  rtp_session_t *s = (rtp_session_t *)cs;
  s->marked_for_deletion = 1;
  return 0;
}

static void delete_all_sessions(void) {
  if (!sessions) return;
  size_t iter = 0;
  void *item;
  while (hashmap_iter(sessions, &iter, &item)) {
    rtp_session_t *s = item;
    s->marked_for_deletion = 1;
  }
}

static int parse_command(const char *cmd, char *cmd_char, char *modifiers, char *call_id,
                         char *remote_ip, int *remote_port, char *from_tag, char *to_tag) {
  *cmd_char = cmd[0];
  modifiers[0] = '\0';

  const char *p = cmd + 1;
  while (*p && *p != ' ' && *p != '\n' && *p != '\r') {
    p++;
  }

  size_t mod_len = (size_t)(p - (cmd + 1));
  if (mod_len > 63) mod_len = 63;
  memcpy(modifiers, cmd + 1, mod_len);
  modifiers[mod_len] = '\0';

  if (*p) p++;

  int n = sscanf(p, "%63s %63s %d %63s", call_id, remote_ip, remote_port, from_tag);
  if (n < 4) {
    return -1;
  }

  const char *tp = strchr(p, ' ');
  if (tp) {
    tp = strchr(tp + 1, ' ');
    if (tp) {
      while (*tp == ' ') tp++;
      size_t to_len = strlen(tp);
      if (to_len > 63) to_len = 63;
      memcpy(to_tag, tp, to_len);
      to_tag[to_len] = '\0';
    }
  }

  return 0;
}

static void handle_command(int fd, const char *cmd, const struct sockaddr *client_addr, socklen_t client_addrlen) {
  char cmd_char = 0;
  char modifiers[64] = {0};
  char call_id[64] = {0};
  char remote_ip[64] = {0};
  int remote_port = 0;
  char from_tag[64] = {0};
  char to_tag[64] = {0};

  if (parse_command(cmd, &cmd_char, modifiers, call_id, remote_ip, &remote_port, from_tag, to_tag) != 0) {
    sendto(fd, "E10\r\n", 6, 0, client_addr, client_addrlen);
    return;
  }

  char response[256];

  switch (cmd_char) {
    case 'U': {
      if (strchr(modifiers, 'T')) {
        sendto(fd, "E20\r\n", 6, 0, client_addr, client_addrlen);
        return;
      }

      rtp_session_t *s = create_session(call_id, from_tag);
      if (!s) {
        sendto(fd, "E18\r\n", 6, 0, client_addr, client_addrlen);
        return;
      }
      if (to_tag[0]) {
        free(s->to_tag);
        s->to_tag = strdup(to_tag);
      }

      int leg_index = 0;
      if (s->leg_a_local_port > 0) {
        leg_index = 1;
      }

      int port = alloc_port_pair();
      if (!port) {
        sendto(fd, "E18\r\n", 6, 0, client_addr, client_addrlen);
        return;
      }

      if (leg_index == 0) {
        s->leg_a_local_port = port;
        if (parse_ip_addr(remote_ip, remote_port, &s->leg_a_remote_addr, &s->leg_a_remote_addrlen) != 0) {
          sendto(fd, "E10\r\n", 6, 0, client_addr, client_addrlen);
          return;
        }
      } else {
        s->leg_b_local_port = port;
        if (parse_ip_addr(remote_ip, remote_port, &s->leg_b_remote_addr, &s->leg_b_remote_addrlen) != 0) {
          sendto(fd, "E10\r\n", 6, 0, client_addr, client_addrlen);
          return;
        }
      }

      spawn_session_pt(s);

      int response_port = (leg_index == 0) ? s->leg_a_local_port : s->leg_b_local_port;
      if (advertise_addr) {
        snprintf(response, sizeof(response), "%d %s\r\n", response_port, advertise_addr);
      } else {
        snprintf(response, sizeof(response), "%d\r\n", response_port);
      }
      sendto(fd, response, strlen(response), 0, client_addr, client_addrlen);
      break;
    }
    case 'L': {
      const rtp_session_t *cs = find_session(call_id);
      if (!cs) {
        sendto(fd, "E16\r\n", 6, 0, client_addr, client_addrlen);
        return;
      }

      int response_port = cs->leg_a_local_port;
      if (advertise_addr) {
        snprintf(response, sizeof(response), "%d %s\r\n", response_port, advertise_addr);
      } else {
        snprintf(response, sizeof(response), "%d\r\n", response_port);
      }
      sendto(fd, response, strlen(response), 0, client_addr, client_addrlen);
      break;
    }
    case 'D': {
      if (delete_session(call_id, from_tag[0] ? from_tag : NULL, to_tag[0] ? to_tag : NULL) != 0) {
        sendto(fd, "E16\r\n", 6, 0, client_addr, client_addrlen);
        return;
      }
      sendto(fd, "0\r\n", 3, 0, client_addr, client_addrlen);
      break;
    }
    case 'X': {
      delete_all_sessions();
      sendto(fd, "0\r\n", 3, 0, client_addr, client_addrlen);
      break;
    }
    case 'Q': {
      snprintf(response, sizeof(response), "0 0 0 0 0\r\n");
      sendto(fd, response, strlen(response), 0, client_addr, client_addrlen);
      break;
    }
    case 'V': {
      snprintf(response, sizeof(response), "20061107\r\n");
      sendto(fd, response, strlen(response), 0, client_addr, client_addrlen);
      break;
    }
    case 'I': {
      snprintf(response, sizeof(response), "upbx rtpproxy builtin\r\n");
      sendto(fd, response, strlen(response), 0, client_addr, client_addrlen);
      break;
    }
    default:
      sendto(fd, "E2\r\n", 5, 0, client_addr, client_addrlen);
      break;
  }
}

static int *create_control_socket(const char *addr) {
  if (strncmp(addr, "unix://", 7) == 0) {
    char *path = strdup(addr + 7);
    int *fds = unix_listen(path, SOCK_DGRAM);
    free(path);
    return fds;
  } else if (strncmp(addr, "tcp://", 6) == 0) {
    return tcp_listen(addr + 6, NULL, NULL);
  } else if (strncmp(addr, "udp://", 6) == 0) {
    return udp_recv(addr + 6, NULL, NULL);
  } else {
    return unix_listen(addr, SOCK_DGRAM);
  }
}

static int get_leg_fds(rtp_session_t *s, int **fds_out) {
  int count_a = s->leg_a_fds ? s->leg_a_fds[0] : 0;
  int count_b = s->leg_b_fds ? s->leg_b_fds[0] : 0;
  int count = count_a + count_b;
  if (count == 0) return 0;

  int *fds = malloc(sizeof(int) * (count + 1));
  if (!fds) return -1;
  fds[0] = 0;

  if (s->leg_a_fds) {
    for (int i = 1; i <= count_a; i++) {
      fds[++fds[0]] = s->leg_a_fds[i];
    }
  }
  if (s->leg_b_fds) {
    for (int i = 1; i <= count_b; i++) {
      fds[++fds[0]] = s->leg_b_fds[i];
    }
  }

  *fds_out = fds;
  return fds[0];
}

static int setup_leg(rtp_session_t *s, int leg) {
  int **leg_fds = (leg == 0) ? &s->leg_a_fds : &s->leg_b_fds;
  int *local_port = (leg == 0) ? &s->leg_a_local_port : &s->leg_b_local_port;
  struct sockaddr_storage *remote_addr = (leg == 0) ? &s->leg_a_remote_addr : &s->leg_b_remote_addr;
  socklen_t *remote_addrlen = (leg == 0) ? &s->leg_a_remote_addrlen : &s->leg_b_remote_addrlen;
  int connect_mode = (leg == 0) ? 0 : s->leg_b_connect_mode;

  if (*leg_fds && (*leg_fds)[0] > 0) return 0;

  if (*local_port <= 0) {
    *local_port = alloc_port_pair();
    if (!*local_port) return -1;
  }

  *leg_fds = create_leg_socket(*local_port);
  if (!*leg_fds) return -1;

  if (connect_mode && *remote_addrlen > 0 && (remote_addr->ss_family == AF_INET || remote_addr->ss_family == AF_INET6)) {
    int conn_fd = connect_to_remote(remote_addr, *remote_addrlen);
    if (conn_fd >= 0) {
      close_leg_fds(*leg_fds);
      *leg_fds = malloc(sizeof(int) * 2);
      (*leg_fds)[0] = 1;
      (*leg_fds)[1] = conn_fd;
    }
  }

  return 0;
}

PT_THREAD(rtp_session_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  rtp_session_t *s = task->udata;

  PT_BEGIN(pt);

  if (setup_leg(s, 0) < 0 || setup_leg(s, 1) < 0) {
    destroy_session(s);
    PT_EXIT(pt);
  }

  int *session_fds = NULL;
  int fd_count = get_leg_fds(s, &session_fds);
  if (fd_count <= 0) {
    destroy_session(s);
    PT_EXIT(pt);
  }

  char buffer[RTP_BUFFER_SIZE];

  for (;;) {
    if (s->marked_for_deletion) {
      break;
    }

    int *ready_fds = NULL;
    PT_WAIT_UNTIL(pt, schedmod_has_data(session_fds, &ready_fds) > 0);

    if (!ready_fds || ready_fds[0] == 0) continue;

    for (int r = 1; r <= ready_fds[0]; r++) {
      int ready_fd = ready_fds[r];

      int is_leg_a = 0, is_leg_b = 0;

      if (s->leg_a_fds) {
        for (int i = 1; i <= s->leg_a_fds[0]; i++) {
          if (ready_fd == s->leg_a_fds[i]) { is_leg_a = 1; break; }
        }
      }
      if (s->leg_b_fds) {
        for (int i = 1; i <= s->leg_b_fds[0]; i++) {
          if (ready_fd == s->leg_b_fds[i]) { is_leg_b = 1; break; }
        }
      }

      ssize_t n;
      struct sockaddr_in from_addr;
      socklen_t from_len = sizeof(from_addr);

      n = recvfrom(ready_fd, buffer, sizeof(buffer) - 1, 0,
                   (struct sockaddr *)&from_addr, &from_len);
      if (n <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          s->marked_for_deletion = 1;
          break;
        }
        continue;
      }

      s->last_activity = time(NULL);

      int dest_fd = -1;
      struct sockaddr *dest_addr = NULL;
      socklen_t dest_addrlen = 0;

      if (is_leg_a && s->leg_b_fds && s->leg_b_fds[0] > 0) {
        dest_fd = s->leg_b_fds[1];
        dest_addr = (struct sockaddr *)&s->leg_b_remote_addr;
        dest_addrlen = s->leg_b_remote_addrlen;
      } else if (is_leg_b && s->leg_a_fds && s->leg_a_fds[0] > 0) {
        dest_fd = s->leg_a_fds[1];
        dest_addr = (struct sockaddr *)&s->leg_a_remote_addr;
        dest_addrlen = s->leg_a_remote_addrlen;
      }

      if (dest_fd >= 0 && dest_addrlen > 0) {
        sendto(dest_fd, buffer, n, 0, dest_addr, dest_addrlen);
      }
    }
    free(ready_fds);
  }

  free(session_fds);

  if (s->marked_for_deletion) {
    destroy_session(s);
  }

  PT_END(pt);
}

static void spawn_session_pt(rtp_session_t *s) {
  schedmod_pt_create(rtp_session_pt, s);
}

PT_THREAD(rtpproxy_server_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp;
  PT_BEGIN(pt);

  PT_WAIT_UNTIL(pt, global_cfg);

  resp_object *rtp_sec = resp_map_get(global_cfg, "rtpproxy");
  if (!rtp_sec) {
    log_info("rtpproxy: no [rtpproxy] section in config, not starting");
    PT_EXIT(pt);
  }

  const char *mode = resp_map_get_string(rtp_sec, "mode");
  if (!mode || strcmp(mode, "builtin") != 0) {
    log_info("rtpproxy: mode is '%s', not starting builtin server", mode ? mode : "(null)");
    PT_EXIT(pt);
  }

  const char *addr_str = resp_map_get_string(rtp_sec, "address");
  control_address = strdup(addr_str);
  if (!control_address) {
    control_address = strdup("/var/run/upbx-rtpproxy.sock");
  }

  const char *ports_str = resp_map_get_string(rtp_sec, "ports");
  if (ports_str) {
    sscanf(ports_str, "%d-%d", &port_low, &port_high);
    if (port_low <= 0) port_low = 10000;
    if (port_high <= port_low) port_high = port_low + 1000;
  }
  port_cur = port_low;

  const char *advertise_cfg = resp_map_get_string(rtp_sec, "advertise");
  if (advertise_cfg) {
    advertise_addr = strdup(advertise_cfg);
  }

  server_sockfds = create_control_socket(control_address);
  if (!server_sockfds || server_sockfds[0] == 0) {
    log_error("rtpproxy: failed to create control socket at %s", control_address);
    free(control_address);
    control_address = NULL;
    PT_EXIT(pt);
  }

  if (!server_sockfds) {
    free(control_address);
    control_address = NULL;
    PT_EXIT(pt);
  }

  log_info("rtpproxy: listening on %s", control_address);

  for (;;) {
    if (global_cfg) {
      resp_object *new_rtp_sec = resp_map_get(global_cfg, "rtpproxy");
      if (new_rtp_sec) {
        const char *new_mode = resp_map_get_string(new_rtp_sec, "mode");
        if (new_mode && strcmp(new_mode, "builtin") != 0) {
          log_info("rtpproxy: mode changed to '%s', shutting down", new_mode);
          break;
        }
      }
    }

    if (server_sockfds && server_sockfds[0] > 0) {
      int *ready_fds = NULL;
      PT_WAIT_UNTIL(pt, schedmod_has_data(server_sockfds, &ready_fds) > 0);

      if (ready_fds && ready_fds[0] > 0) {
        for (int r = 1; r <= ready_fds[0]; r++) {
          int ready_fd = ready_fds[r];

          char cmdbuf[1024];
          struct sockaddr_un client_addr;
          socklen_t client_len = sizeof(client_addr);
          ssize_t cmdlen = recvfrom(ready_fd, cmdbuf, sizeof(cmdbuf) - 1, 0,
                                    (struct sockaddr *)&client_addr, &client_len);

          if (cmdlen <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
              log_error("rtpproxy: recvfrom failed: %s", strerror(errno));
            }
          } else {
            cmdbuf[cmdlen] = '\0';
            while (cmdlen > 0 && (cmdbuf[cmdlen - 1] == '\n' || cmdbuf[cmdlen - 1] == '\r')) {
              cmdbuf[--cmdlen] = '\0';
            }

            if (cmdlen == 0) {
              PT_YIELD(pt);
              continue;
            }

            log_trace("rtpproxy: command: %s", cmdbuf);

            int new_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (new_fd >= 0) {
              handle_command(new_fd, cmdbuf, (struct sockaddr *)&client_addr, client_len);
              close(new_fd);
            }
          }
        }
        free(ready_fds);
      }
    } else {
      PT_YIELD(pt);
    }
  }

  if (server_sockfds) {
    for (int i = 1; i <= server_sockfds[0]; i++) {
      close(server_sockfds[i]);
    }
    free(server_sockfds);
    server_sockfds = NULL;
  }

  if (sessions) {
    size_t iter = 0;
    void *item;
    while (hashmap_iter(sessions, &iter, &item)) {
      rtp_session_t *s = item;
      remove_session(s);
    }
    hashmap_free(sessions);
    sessions = NULL;
  }

  free(control_address);
  control_address = NULL;
  free(advertise_addr);
  advertise_addr = NULL;

  PT_END(pt);
}
