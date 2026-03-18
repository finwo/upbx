#include "udphole/client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "finwo/resp.h"
#include "finwo/socket-util.h"
#include "rxi/log.h"

#define READ_BUF_SIZE 4096

static void client_close(struct udphole_client *client);
static int client_connect_next(struct udphole_client *client);
static int send_command(struct udphole_client *client, const char *cmd);
static int parse_response(struct udphole_client *client, resp_object **out);

struct udphole_client *udphole_client_create(struct upbx_config *config) {
  fprintf(stderr, "DEBUG udphole_client_create: start\n");
  fflush(stderr);
  struct udphole_client *client = calloc(1, sizeof(*client));
  fprintf(stderr, "DEBUG udphole_client_create: allocated client\n");
  fflush(stderr);
  client->config = config;
  client->fd = -1;

  fprintf(stderr, "DEBUG udphole_client_create: counting rtpproxies\n");
  fflush(stderr);
  struct upbx_rtpproxy *r = config->rtpproxies;
  int count = 0;
  if (r) {
    count = 1;
    while (r->next && r->next != config->rtpproxies) {
      count++;
      r = r->next;
    }
  }
  fprintf(stderr, "DEBUG udphole_client_create: found %d rtpproxies\n", count);
  fflush(stderr);
  client->max_retries = count > 0 ? count : 1;
  client->retry_count = 0;

  fprintf(stderr, "DEBUG udphole_client_create: calling client_connect_next\n");
  fflush(stderr);
  int res = client_connect_next(client);
  fprintf(stderr, "DEBUG udphole_client_create: client_connect_next returned %d\n", res);
  fflush(stderr);

  return client;
}

void udphole_client_destroy(struct udphole_client *client) {
  if (!client) return;
  client_close(client);
  free(client->wbuf);
  free(client->connected_url);
  free(client);
}

static void client_close(struct udphole_client *client) {
  if (client->fd >= 0) {
    close(client->fd);
    client->fd = -1;
  }
}

static int connect_unix(struct udphole_client *client, const char *path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    close(fd);
    return -1;
  }

  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(fd, &fds);
  struct timeval tv = {2, 0};
  ret = select(fd + 1, NULL, &fds, NULL, &tv);
  if (ret <= 0) {
    close(fd);
    return -1;
  }

  int soerror = 0;
  socklen_t len = sizeof(soerror);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerror, &len);
  if (soerror != 0) {
    close(fd);
    return -1;
  }

  fcntl(fd, F_SETFL, flags);
  client->fd = fd;
  memset(&client->remote_addr, 0, sizeof(client->remote_addr));

  return 0;
}

static int connect_tcp(struct udphole_client *client, const char *host, const char *port) {
  struct addrinfo hints, *res, *res0;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int error = getaddrinfo(host, port, &hints, &res0);
  if (error) return -1;

  int fd = -1;
  for (res = res0; res; res = res->ai_next) {
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) continue;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, res->ai_addr, res->ai_addrlen);
    if (ret < 0 && errno != EINPROGRESS) {
      close(fd);
      fd = -1;
      continue;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv = {2, 0};
    ret = select(fd + 1, NULL, &fds, NULL, &tv);
    if (ret <= 0) {
      close(fd);
      fd = -1;
      continue;
    }

    int soerror = 0;
    socklen_t len = sizeof(soerror);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerror, &len);
    if (soerror != 0) {
      close(fd);
      fd = -1;
      continue;
    }

    fcntl(fd, F_SETFL, flags);
    break;
  }

  freeaddrinfo(res0);

  if (fd < 0) return -1;

  client->fd = fd;
  memcpy(&client->remote_addr, res->ai_addr, res->ai_addrlen);

  return 0;
}

static int client_connect_next(struct udphole_client *client) {
  fprintf(stderr, "DEBUG client_connect_next: start\n");
  fflush(stderr);
  if (!client->config || !client->config->rtpproxies) {
    fprintf(stderr, "DEBUG client_connect_next: no config or rtpproxies\n");
    fflush(stderr);
    return -1;
  }

  fprintf(stderr, "DEBUG client_connect_next: calling client_close\n");
  fflush(stderr);
  client_close(client);
  fprintf(stderr, "DEBUG client_connect_next: after client_close\n");
  fflush(stderr);

  if (!client->current_rtpproxy) {
    fprintf(stderr, "DEBUG client_connect_next: setting current_rtpproxy\n");
    fflush(stderr);
    client->current_rtpproxy = client->config->rtpproxies;
  }

  struct upbx_rtpproxy *start = client->current_rtpproxy;
  fprintf(stderr, "DEBUG client_connect_next: start=%p, max_retries=%d\n", (void*)start, client->max_retries);
  fflush(stderr);
  int attempts = 0;

  while (attempts < client->max_retries) {
    fprintf(stderr, "DEBUG client_connect_next: loop attempt %d\n", attempts);
    fflush(stderr);
    struct upbx_rtpproxy *rtp = client->current_rtpproxy;
    fprintf(stderr, "DEBUG client_connect_next: rtp=%p\n", (void*)rtp);
    fflush(stderr);
    if (!rtp) {
      fprintf(stderr, "DEBUG client_connect_next: rtp is NULL\n");
      fflush(stderr);
      break;
    }
    client->current_rtpproxy = rtp->next;
    fprintf(stderr, "DEBUG client_connect_next: advanced rtp\n");
    fflush(stderr);
    if (!client->current_rtpproxy) {
      client->current_rtpproxy = client->config->rtpproxies;
    }

    if (!rtp->url) {
      fprintf(stderr, "DEBUG client_connect_next: no url, continue\n");
      fflush(stderr);
      attempts++;
      continue;
    }

    free(client->connected_url);
    client->connected_url = NULL;

    fprintf(stderr, "DEBUG client_connect_next: trying url scheme=%s\n", rtp->url->scheme ? rtp->url->scheme : "null");
    fflush(stderr);
    char addr_buf[512];
    if (rtp->url->scheme && strcmp(rtp->url->scheme, "unix") == 0) {
      fprintf(stderr, "DEBUG client_connect_next: unix path=%s\n", rtp->url->path ? rtp->url->path : "null");
      fflush(stderr);
      int res = connect_unix(client, rtp->url->path);
      fprintf(stderr, "DEBUG client_connect_next: connect_unix result=%d\n", res);
      fflush(stderr);
      if (res == 0) {
        client->current_rtpproxy = rtp;
        client->connected_url = strdup(rtp->url->path);
        client->retry_count = 0;
        log_info("udphole: connected to %s", rtp->url->path);

        if (rtp->url->username && rtp->url->password) {
          char cmd[512];
          snprintf(cmd, sizeof(cmd), "AUTH %s %s\r\n", rtp->url->username, rtp->url->password);
          send_command(client, cmd);
        }

        return 0;
      }
    } else if (rtp->url->scheme && (strcmp(rtp->url->scheme, "tcp") == 0 || strcmp(rtp->url->scheme, "sip") == 0)) {
      const char *host = rtp->url->host ? rtp->url->host : "localhost";
      const char *port = rtp->url->port ? rtp->url->port : "6379";

      if (connect_tcp(client, host, port) == 0) {
        snprintf(addr_buf, sizeof(addr_buf), "tcp://%s:%s", host, port);
        client->current_rtpproxy = rtp;
        free(client->connected_url);
        client->connected_url = strdup(addr_buf);
        client->retry_count = 0;
        log_info("udphole: connected to %s:%s", host, port);

        if (rtp->url->username && rtp->url->password) {
          char cmd[512];
          snprintf(cmd, sizeof(cmd), "AUTH %s %s\r\n", rtp->url->username, rtp->url->password);
          send_command(client, cmd);
        }

        return 0;
      }
    }

    attempts++;
  }

  client->retry_count++;
  log_warn("udphole: failed to connect after %d attempts", client->retry_count);

  return -1;
}

int udphole_client_connect(struct udphole_client *client, udphole_connect_cb cb, void *udata) {
  (void)cb;
  (void)udata;

  if (client->fd >= 0) {
    return 0;
  }

  return client_connect_next(client);
}

void udphole_client_disconnect(struct udphole_client *client) {
  client_close(client);
}

static int send_command(struct udphole_client *client, const char *cmd) {
  if (client->fd < 0) return -1;

  size_t len = strlen(cmd);
  ssize_t n = send(client->fd, cmd, len, 0);
  return (n == (ssize_t)len) ? 0 : -1;
}

static int parse_response(struct udphole_client *client, resp_object **out) {
  if (!out) return -1;

  resp_object *resp = NULL;
  int consumed = resp_read_buf(client->rbuf, client->rlen, &resp);

  if (consumed > 0) {
    memmove(client->rbuf, client->rbuf + consumed, client->rlen - consumed);
    client->rlen -= consumed;
    *out = resp;
    return 0;
  } else if (consumed < 0) {
    *out = NULL;
    return 1;
  }

  *out = NULL;
  return 1;
}

static int wait_response(struct udphole_client *client, resp_object **out) {
  if (client->fd < 0) return -1;

  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(client->fd, &fds);

  struct timeval tv = {1, 0};
  int ret = select(client->fd + 1, &fds, NULL, NULL, &tv);
  if (ret <= 0) return -1;

  char buf[READ_BUF_SIZE];
  ssize_t n = recv(client->fd, buf, sizeof(buf) - 1, 0);
  if (n <= 0) return -1;

  if (client->rlen + n > sizeof(client->rbuf)) {
    memmove(client->rbuf, client->rbuf + 1024, client->rlen - 1024);
    client->rlen -= 1024;
  }
  memcpy(client->rbuf + client->rlen, buf, n);
  client->rlen += n;

  return parse_response(client, out);
}

int udphole_client_session_create(struct udphole_client *client, const char *session_id, int idle_expiry) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.CREATE %s %d\r\n", session_id, idle_expiry);

  for (int i = 0; i < client->max_retries; i++) {
    if (client->fd < 0) {
      if (client_connect_next(client) != 0) continue;
    }

    if (send_command(client, cmd) != 0) {
      client_close(client);
      client_connect_next(client);
      continue;
    }

    resp_object *resp = NULL;
    if (wait_response(client, &resp) == 0 && resp) {
      int is_ok = (resp->type == RESPT_ARRAY && resp->u.arr.n >= 1 &&
                   resp->u.arr.elem[0].type == RESPT_BULK &&
                   strcmp(resp->u.arr.elem[0].u.s, "OK") == 0);
      resp_free(resp);
      if (is_ok) return 0;

      resp_free(resp);
    }

    client_close(client);
    client_connect_next(client);
  }

  return -1;
}

int udphole_client_session_destroy(struct udphole_client *client, const char *session_id) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.DESTROY %s\r\n", session_id);

  if (client->fd < 0) return -1;

  send_command(client, cmd);

  resp_object *resp = NULL;
  wait_response(client, &resp);
  resp_free(resp);

  return 0;
}

int udphole_client_socket_create_listen(struct udphole_client *client, const char *session_id, const char *socket_id, struct udphole_socket_info *info) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.SOCKET.CREATE.LISTEN %s %s\r\n", session_id, socket_id);

  for (int i = 0; i < client->max_retries; i++) {
    if (client->fd < 0) {
      if (client_connect_next(client) != 0) continue;
    }

    if (send_command(client, cmd) != 0) {
      client_close(client);
      client_connect_next(client);
      continue;
    }

    resp_object *resp = NULL;
    if (wait_response(client, &resp) == 0 && resp && resp->type == RESPT_ARRAY && resp->u.arr.n >= 2) {
      int port = 0;
      char *ip = NULL;

      if (resp->u.arr.elem[0].type == RESPT_INT) {
        port = (int)resp->u.arr.elem[0].u.i;
      }

      if (resp->u.arr.n >= 2 && resp->u.arr.elem[1].type == RESPT_BULK) {
        if (resp->u.arr.elem[1].u.s && resp->u.arr.elem[1].u.s[0]) {
          ip = resp->u.arr.elem[1].u.s;
        }
      }

      if (port > 0) {
        info->socket_id = strdup(socket_id);
        info->local_port = port;
        info->advertised_ip = ip ? strdup(ip) : NULL;
        resp_free(resp);
        return 0;
      }

      resp_free(resp);
    }

    client_close(client);
    client_connect_next(client);
  }

  return -1;
}

int udphole_client_socket_create_connect(struct udphole_client *client, const char *session_id, const char *socket_id, const char *ip, int port, struct udphole_socket_info *info) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.SOCKET.CREATE.CONNECT %s %s %s %d\r\n", session_id, socket_id, ip, port);

  if (client->fd < 0) return -1;

  send_command(client, cmd);

  resp_object *resp = NULL;
  if (wait_response(client, &resp) == 0 && resp && resp->type == RESPT_ARRAY && resp->u.arr.n >= 2) {
    int local_port = 0;
    char *advertised_ip = NULL;

    if (resp->u.arr.elem[0].type == RESPT_INT) {
      local_port = (int)resp->u.arr.elem[0].u.i;
    }

    if (resp->u.arr.n >= 2 && resp->u.arr.elem[1].type == RESPT_BULK) {
      if (resp->u.arr.elem[1].u.s && resp->u.arr.elem[1].u.s[0]) {
        advertised_ip = resp->u.arr.elem[1].u.s;
      }
    }

    if (local_port > 0) {
      info->socket_id = strdup(socket_id);
      info->local_port = local_port;
      info->advertised_ip = advertised_ip ? strdup(advertised_ip) : NULL;
      resp_free(resp);
      return 0;
    }

    resp_free(resp);
  }

  return -1;
}

int udphole_client_socket_destroy(struct udphole_client *client, const char *session_id, const char *socket_id) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.SOCKET.DESTROY %s %s\r\n", session_id, socket_id);

  if (client->fd < 0) return -1;

  send_command(client, cmd);

  resp_object *resp = NULL;
  wait_response(client, &resp);
  resp_free(resp);

  return 0;
}

int udphole_client_forward_create(struct udphole_client *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.FORWARD.CREATE %s %s %s\r\n", session_id, src_socket_id, dst_socket_id);

  if (client->fd < 0) return -1;

  for (int i = 0; i < client->max_retries; i++) {
    if (send_command(client, cmd) != 0) {
      client_close(client);
      client_connect_next(client);
      continue;
    }

    resp_object *resp = NULL;
    if (wait_response(client, &resp) == 0 && resp) {
      int is_ok = (resp->type == RESPT_ARRAY && resp->u.arr.n >= 1 &&
                   resp->u.arr.elem[0].type == RESPT_BULK &&
                   strcmp(resp->u.arr.elem[0].u.s, "OK") == 0);
      resp_free(resp);
      if (is_ok) return 0;
      resp_free(resp);
    }

    client_close(client);
    client_connect_next(client);
  }

  return -1;
}

int udphole_client_forward_destroy(struct udphole_client *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "SESSION.FORWARD.DESTROY %s %s %s\r\n", session_id, src_socket_id, dst_socket_id);

  if (client->fd < 0) return -1;

  send_command(client, cmd);

  resp_object *resp = NULL;
  wait_response(client, &resp);
  resp_free(resp);

  return 0;
}

int udphole_client_get_fds(struct udphole_client *client, int **fds) {
  if (!fds) return 0;
  *fds = NULL;
  if (client->fd < 0) return 0;

  *fds = malloc(sizeof(int) * 2);
  (*fds)[0] = 1;
  (*fds)[1] = client->fd;
  return 1;
}

const char *udphole_client_get_advertised_ip(struct udphole_client *client) {
  if (!client->current_rtpproxy || !client->current_rtpproxy->url) {
    return NULL;
  }

  if (client->current_rtpproxy->url->scheme &&
      strcmp(client->current_rtpproxy->url->scheme, "unix") == 0) {
    return NULL;
  }

  return client->current_rtpproxy->url->host;
}
