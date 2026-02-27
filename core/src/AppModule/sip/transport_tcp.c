#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "common/pt.h"
#include "common/socket_util.h"
#include "config.h"
#include "AppModule/scheduler/daemon.h"
#include "AppModule/sip/transport_tcp.h"

#define TCP_BUF_SIZE 16384

typedef struct {
  int fd;
  char buf[TCP_BUF_SIZE];
  size_t rlen;
} tcp_client_state_t;

static int tcp_listen_fd = -1;

PT_THREAD(sip_tcp_client_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  tcp_client_state_t *state = task->udata;

  PT_BEGIN(pt);

  task->read_fds = &state->fd;
  task->read_fds_count = 1;

  for (;;) {
    int ready_fd = -1;
    PT_WAIT_UNTIL(pt, pt_task_has_data(task, &ready_fd) == 0 && ready_fd == state->fd);

    size_t space = sizeof(state->buf) - state->rlen;
    if (space == 0) {
      break;
    }

    ssize_t n = recv(state->fd, state->buf + state->rlen, space, 0);
    if (n <= 0) {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        break;
      }
    }
    state->rlen += (size_t)n;

    char *body = memmem(state->buf, state->rlen, "\r\n\r\n", 4);
    if (!body) continue;
    body += 4;

    size_t header_len = (size_t)(body - state->buf);

    int content_length = 0;
    char *cl = memmem(state->buf, header_len, "Content-Length:", 15);
    if (cl) {
      cl += 15;
      while (*cl == ' ') cl++;
      content_length = atoi(cl);
    }

    size_t total_len = header_len + content_length;
    if (state->rlen < total_len) continue;

    state->buf[total_len] = '\0';
    log_trace("sip_tcp: received %zu bytes", total_len);

    (void)timestamp;
  }

  if (state->fd >= 0) {
    close(state->fd);
  }
  free(state);

  PT_END(pt);
}

PT_THREAD(sip_tcp_listener_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  PT_BEGIN(pt);

  char *listen_addr = config_get_listen();
  if (!listen_addr) {
    listen_addr = strdup("0.0.0.0:5060");
  }

  char host[256] = "0.0.0.0";
  int port = 5060;
  const char *colon = strrchr(listen_addr, ':');
  if (colon) {
    size_t hlen = (size_t)(colon - listen_addr);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, listen_addr, hlen);
    host[hlen] = '\0';
    port = atoi(colon + 1);
  }
  free(listen_addr);

  tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (tcp_listen_fd < 0) {
    log_error("sip_tcp: socket failed: %s", strerror(errno));
    PT_EXIT(pt);
  }

  int opt = 1;
  setsockopt(tcp_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(host);
  addr.sin_port = htons(port);

  if (bind(tcp_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    log_error("sip_tcp: bind failed: %s", strerror(errno));
    close(tcp_listen_fd);
    tcp_listen_fd = -1;
    PT_EXIT(pt);
  }

  if (listen(tcp_listen_fd, 10) < 0) {
    log_error("sip_tcp: listen failed: %s", strerror(errno));
    close(tcp_listen_fd);
    tcp_listen_fd = -1;
    PT_EXIT(pt);
  }

  set_socket_nonblocking(tcp_listen_fd, 1);

  task->read_fds = &tcp_listen_fd;
  task->read_fds_count = 1;

  log_info("sip_tcp: listening on %s:%d", host, port);

  for (;;) {
    int ready_fd = -1;
    PT_WAIT_UNTIL(pt, pt_task_has_data(task, &ready_fd) == 0 && ready_fd == tcp_listen_fd);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int new_fd = accept(tcp_listen_fd, (struct sockaddr *)&client_addr, &client_len);

    if (new_fd < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        log_error("sip_tcp: accept failed: %s", strerror(errno));
      }
      continue;
    }

    set_socket_nonblocking(new_fd, 1);

    tcp_client_state_t *state = calloc(1, sizeof(*state));
    if (!state) {
      close(new_fd);
      continue;
    }
    state->fd = new_fd;

    appmodule_pt_add(sip_tcp_client_pt, state);
    log_trace("sip_tcp: accepted connection, spawned client pt");
  }

  PT_END(pt);
}

void sip_tcp_start(void) {
  appmodule_pt_add(sip_tcp_listener_pt, NULL);
}

void sip_tcp_stop(void) {
  if (tcp_listen_fd >= 0) {
    close(tcp_listen_fd);
    tcp_listen_fd = -1;
  }
}