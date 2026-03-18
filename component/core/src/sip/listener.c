#include "sip/listener.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "finwo/socket-util.h"
#include "rxi/log.h"

#define BUF_SIZE 8192

struct sip_listener *sip_listener_create(struct upbx_config *config) {
  struct sip_listener *listener = calloc(1, sizeof(*listener));
  listener->config = config;
  listener->fds = NULL;
  return listener;
}

void sip_listener_destroy(struct sip_listener *listener) {
  if (!listener) return;

  if (listener->fds) {
    for (int i = 1; i <= listener->fds[0]; i++) {
      if (listener->fds[i] >= 0) {
        close(listener->fds[i]);
      }
    }
    free(listener->fds);
  }

  free(listener);
}

int sip_listener_listen(struct sip_listener *listener, const char *addr) {
  if (!listener || !addr) return -1;

  listener->fds = udp_recv(addr, "", "5060");
  if (!listener->fds) {
    log_error("sip: failed to listen on %s", addr);
    return -1;
  }

  log_info("sip: listening on %s", addr);
  return 0;
}

int sip_listener_set_handler(struct sip_listener *listener, sip_request_cb cb, void *udata) {
  if (!listener) return -1;
  listener->on_request = cb;
  listener->user_data = udata;
  return 0;
}

int sip_listener_send(struct sip_listener *listener, const struct sockaddr_storage *dst, const char *data, size_t len) {
  if (!listener || !dst || !data) return -1;

  int fd = listener->fds[1];
  ssize_t sent = sendto(fd, data, len, 0, (const struct sockaddr *)dst, sizeof(*dst));
  return (sent == (ssize_t)len) ? 0 : -1;
}

static void handle_request(struct sip_listener *listener, const char *buf, size_t len, const struct sockaddr_storage *src) {
  struct sip_request *req = sip_parse_request(buf, len);
  if (!req) {
    log_warn("sip: failed to parse request");
    return;
  }

  char src_str[128];
  if (src->ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)src;
    inet_ntop(AF_INET, &sin->sin_addr, src_str, sizeof(src_str));
  } else if (src->ss_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src;
    inet_ntop(AF_INET6, &sin6->sin6_addr, src_str, sizeof(src_str));
  } else {
    snprintf(src_str, sizeof(src_str), "unknown");
  }

  log_debug("sip: received %s from %s", req->method_str, src_str);

  if (listener->on_request) {
    listener->on_request(req, src, NULL, listener->user_data);
  }
}

int sip_listener_process(struct sip_listener *listener) {
  if (!listener || !listener->fds) return -1;

  char buf[BUF_SIZE];
  struct sockaddr_storage src;
  socklen_t src_len = sizeof(src);

  for (int i = 1; i <= listener->fds[0]; i++) {
    int fd = listener->fds[i];

    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &src_len);
    if (n <= 0) {
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        continue;
      }
      continue;
    }

    buf[n] = '\0';
    handle_request(listener, buf, n, &src);
  }

  return 0;
}
