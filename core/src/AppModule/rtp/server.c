#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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
#include "common/pt.h"
#include "common/socket_util.h"
#include "config.h"
#include "AppModule/scheduler/daemon.h"
#include "AppModule/rtp/server.h"

#define RTP_SESSION_HASH_SIZE 256

typedef struct rtp_session {
  char *call_id;
  char *from_tag;
  char *to_tag;
  char *remote_ip;
  int remote_port;
  int local_port;
  int rtp_fd;
  int rtcp_fd;
  int created;
  int last_activity;
  struct rtp_session *next;
} rtp_session_t;

static rtp_session_t *sessions[RTP_SESSION_HASH_SIZE];
static int server_sockfd = -1;
static int server_running = 0;
static int port_low = 10000;
static int port_high = 20000;
static char *advertise_addr = NULL;

static int port_cur = 10000;

static unsigned int hash_call_id(const char *call_id) {
  unsigned int hash = 5381;
  for (const char *p = call_id; *p; p++) {
    hash = ((hash << 5) + hash) + (unsigned char)*p;
  }
  return hash % RTP_SESSION_HASH_SIZE;
}

static rtp_session_t *find_session(const char *call_id, const char *from_tag) {
  unsigned int h = hash_call_id(call_id);
  for (rtp_session_t *s = sessions[h]; s; s = s->next) {
    if (strcmp(s->call_id, call_id) == 0 && 
        (from_tag == NULL || strcmp(s->from_tag, from_tag) == 0)) {
      return s;
    }
  }
  return NULL;
}

static void remove_session(rtp_session_t *s) {
  if (s->rtp_fd >= 0) close(s->rtp_fd);
  if (s->rtcp_fd >= 0) close(s->rtcp_fd);
  free(s->call_id);
  free(s->from_tag);
  free(s->to_tag);
  free(s->remote_ip);
  free(s);
}

static int alloc_port_pair(void) {
  for (int i = 0; i < port_high - port_low; i++) {
    int port = port_cur + i;
    if (port > port_high) port = port_low;
    port_cur = port + 2;
    if (port_cur > port_high) port_cur = port_low;

    int rtp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (rtp_fd < 0) continue;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(rtp_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      close(rtp_fd);
      return port;
    }
    close(rtp_fd);
  }
  return 0;
}

static rtp_session_t *create_session(const char *call_id, const char *remote_ip, int remote_port, const char *from_tag) {
  rtp_session_t *s = find_session(call_id, from_tag);
  if (s) return s;

  int port = alloc_port_pair();
  if (!port) {
    log_error("rtp_server: no ports available");
    return NULL;
  }

  s = calloc(1, sizeof(*s));
  if (!s) return NULL;

  s->call_id = strdup(call_id);
  s->from_tag = strdup(from_tag);
  s->remote_ip = strdup(remote_ip);
  s->remote_port = remote_port;
  s->local_port = port;
  s->rtp_fd = -1;
  s->rtcp_fd = -1;
  s->created = time(NULL);
  s->last_activity = s->created;

  unsigned int h = hash_call_id(call_id);
  s->next = sessions[h];
  sessions[h] = s;

  log_debug("rtp_server: created session %s/%s port %d", call_id, from_tag, port);
  return s;
}

static int delete_session(const char *call_id, const char *from_tag, const char *to_tag) {
  unsigned int h = hash_call_id(call_id);
  rtp_session_t **prev = &sessions[h];
  
  for (rtp_session_t *s = *prev; s; prev = &s->next, s = s->next) {
    if (strcmp(s->call_id, call_id) == 0 && 
        (from_tag == NULL || strcmp(s->from_tag, from_tag) == 0)) {
      if (to_tag && s->to_tag && strcmp(s->to_tag, to_tag) != 0) {
        continue;
      }
      *prev = s->next;
      log_debug("rtp_server: deleted session %s/%s", call_id, from_tag);
      remove_session(s);
      return 0;
    }
  }
  return -1;
}

static void delete_all_sessions(void) {
  for (int i = 0; i < RTP_SESSION_HASH_SIZE; i++) {
    rtp_session_t *s = sessions[i];
    while (s) {
      rtp_session_t *next = s->next;
      remove_session(s);
      s = next;
    }
    sessions[i] = NULL;
  }
}

static int parse_command(const char *cmd, char *cmd_char, char *call_id, char *remote_ip, int *remote_port, char *from_tag, char *to_tag) {
  *cmd_char = cmd[0];
  
  const char *p = cmd + 1;
  while (*p && *p != ' ') p++;
  if (*p) {
    size_t len = p - (cmd + 1);
    if (len > 63) len = 63;
    memcpy(call_id, cmd + 1, len);
    call_id[len] = '\0';
    p++;
  } else {
    call_id[0] = '\0';
    return -1;
  }

  if (sscanf(p, "%63s %d %63s", remote_ip, remote_port, from_tag) < 3) {
    return -1;
  }

  const char *tp = strchr(p, ' ');
  if (tp) {
    tp = strchr(tp + 1, ' ');
    if (tp) {
      while (*tp == ' ') tp++;
      strncpy(to_tag, tp, 63);
      to_tag[63] = '\0';
    }
  }

  return 0;
}

static void handle_command(int fd, const char *cmd) {
  char cmd_char = 0;
  char call_id[64] = {0};
  char remote_ip[64] = {0};
  int remote_port = 0;
  char from_tag[64] = {0};
  char to_tag[64] = {0};

  if (parse_command(cmd, &cmd_char, call_id, remote_ip, &remote_port, from_tag, to_tag) != 0) {
    send(fd, "E10\r\n", 6, 0);
    return;
  }

  char response[256];

  switch (cmd_char) {
    case 'U': {
      rtp_session_t *s = create_session(call_id, remote_ip, remote_port, from_tag);
      if (!s) {
        send(fd, "E18\r\n", 6, 0);
        return;
      }
      if (to_tag[0]) {
        free(s->to_tag);
        s->to_tag = strdup(to_tag);
      }
      if (advertise_addr) {
        snprintf(response, sizeof(response), "%d %s\r\n", s->local_port, advertise_addr);
      } else {
        snprintf(response, sizeof(response), "%d\r\n", s->local_port);
      }
      send(fd, response, strlen(response), 0);
      break;
    }
    case 'L': {
      rtp_session_t *s = find_session(call_id, from_tag);
      if (!s) {
        send(fd, "E16\r\n", 6, 0);
        return;
      }
      if (advertise_addr) {
        snprintf(response, sizeof(response), "%d %s\r\n", s->local_port, advertise_addr);
      } else {
        snprintf(response, sizeof(response), "%d\r\n", s->local_port);
      }
      send(fd, response, strlen(response), 0);
      break;
    }
    case 'D': {
      if (delete_session(call_id, from_tag, to_tag[0] ? to_tag : NULL) != 0) {
        send(fd, "E16\r\n", 6, 0);
        return;
      }
      send(fd, "0\r\n", 3, 0);
      break;
    }
    case 'X': {
      delete_all_sessions();
      send(fd, "0\r\n", 3, 0);
      break;
    }
    case 'Q': {
      snprintf(response, sizeof(response), "0 0 0 0 0\r\n");
      send(fd, response, strlen(response), 0);
      break;
    }
    default:
      send(fd, "E2\r\n", 5, 0);
      break;
  }
}

PT_THREAD(rtp_server_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  static char cmdbuf[1024];
  static int cmdlen = 0;

  PT_BEGIN(pt);

  char *socket_path = config_get_rtp_socket();
  if (!socket_path) {
    socket_path = strdup("/var/run/rtpproxy.sock");
  }

  port_low = config_get_rtp_port_low();
  port_high = config_get_rtp_port_high();
  port_cur = port_low;

  free(advertise_addr);
  advertise_addr = config_get_rtp_advertise_addr();

  unlink(socket_path);

  server_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (server_sockfd < 0) {
    log_error("rtp_server: socket failed: %s", strerror(errno));
    free(socket_path);
    PT_EXIT(pt);
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (bind(server_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    log_error("rtp_server: bind failed: %s", strerror(errno));
    close(server_sockfd);
    server_sockfd = -1;
    free(socket_path);
    PT_EXIT(pt);
  }

  chmod(socket_path, 0777);
  free(socket_path);

  set_socket_nonblocking(server_sockfd, 1);

  task->read_fds = &server_sockfd;
  task->read_fds_count = 1;
  server_running = 1;

  log_info("rtp_server: listening on %s", config_get_rtp_socket());

  for (;;) {
    int ready_fd = -1;
    PT_WAIT_UNTIL(pt, pt_task_has_data(task, &ready_fd) == 0 && ready_fd == server_sockfd);

    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);
    cmdlen = recvfrom(server_sockfd, cmdbuf, sizeof(cmdbuf) - 1, 0,
                      (struct sockaddr *)&client_addr, &client_len);

    if (cmdlen <= 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        log_error("rtp_server: recvfrom failed: %s", strerror(errno));
      }
      continue;
    }

    cmdbuf[cmdlen] = '\0';
    while (cmdlen > 0 && (cmdbuf[cmdlen - 1] == '\n' || cmdbuf[cmdlen - 1] == '\r')) {
      cmdbuf[--cmdlen] = '\0';
    }

    if (cmdlen == 0) continue;

    log_trace("rtp_server: command: %s", cmdbuf);

    int new_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (new_fd >= 0) {
      handle_command(new_fd, cmdbuf);
      close(new_fd);
    }
  }

  PT_END(pt);
}

void rtp_server_start(void) {
  if (server_running) return;
  char *mode = config_get_rtp_mode();
  if (mode && strcmp(mode, "builtin") != 0) {
    log_info("rtp_server: mode is '%s', not starting builtin server", mode);
    free(mode);
    return;
  }
  free(mode);
  appmodule_pt_add(rtp_server_pt, NULL);
}

void rtp_server_stop(void) {
  if (server_sockfd >= 0) {
    close(server_sockfd);
    server_sockfd = -1;
  }
  delete_all_sessions();
  server_running = 0;
}

int rtp_server_is_running(void) {
  return server_running;
}