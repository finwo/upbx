#include "domain/pbx/media_proxy.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>

#include "common/resp.h"
#include "domain/config.h"
#include "finwo/mindex.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

typedef struct rtpproxy_node {
  char *url;
  struct parsed_url *parsed;
  struct rtpproxy_node *next;
  struct rtpproxy_node *prev;
} rtpproxy_node_t;

static rtpproxy_node_t *rtpproxy_list = NULL;
static rtpproxy_node_t *rtpproxy_current = NULL;
static int client_fd = -1;
static int connected = 0;

static int parse_rtpproxy_config(void) {
  if (!domain_cfg) {
    log_warn("pbx: domain_cfg is NULL");
    return -1;
  }

  resp_object *upbx_sec = resp_map_get(domain_cfg, "upbx");
  if (!upbx_sec) {
    log_warn("pbx: no [upbx] section in config");
    return -1;
  }

  resp_object *rtpproxies = resp_map_get(upbx_sec, "rtpproxy");
  if (!rtpproxies) {
    log_warn("pbx: no rtpproxy key in [upbx] section");
    return -1;
  }
  if (rtpproxies->type != RESPT_ARRAY) {
    log_warn("pbx: rtpproxy is not an array (type=%d)", rtpproxies->type);
    return -1;
  }
  if (rtpproxies->u.arr.n == 0) {
    log_warn("pbx: rtpproxy array is empty");
    return -1;
  }

  log_info("pbx: found %zu rtpproxy entries", rtpproxies->u.arr.n);

  rtpproxy_node_t *head = NULL;
  rtpproxy_node_t *tail = NULL;

  for (size_t i = 0; i < rtpproxies->u.arr.n; i++) {
    const char *url = resp_map_get_string(&rtpproxies->u.arr.elem[i], "_value");
    if (!url) continue;

    rtpproxy_node_t *node = calloc(1, sizeof(rtpproxy_node_t));
    node->url = strdup(url);
    node->parsed = parse_url(url);

    if (!head) {
      head = node;
      tail = node;
    } else {
      tail->next = node;
      node->prev = tail;
      tail = node;
    }
  }

  if (head && tail) {
    tail->next = head;
    head->prev = tail;
    rtpproxy_list = head;
    rtpproxy_current = head;
    return 0;
  }

  return -1;
}

static int connect_to_url(struct parsed_url *parsed) {
  if (!parsed || !parsed->host) return -1;

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  if (strcmp(parsed->scheme, "unix") == 0) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, parsed->path ? parsed->path : parsed->host, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      close(fd);
      return -1;
    }
    return fd;
  }

  int port = parsed->port ? atoi(parsed->port) : 6379;
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  if (getaddrinfo(parsed->host, port_str, &hints, &res) != 0 || !res) {
    if (res) freeaddrinfo(res);
    return -1;
  }

  if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
    freeaddrinfo(res);
    close(fd);
    return -1;
  }
  freeaddrinfo(res);

  return fd;
}

static void switch_to_next_rtpproxy(void) {
  if (rtpproxy_current) {
    rtpproxy_current = rtpproxy_current->next;
  } else {
    rtpproxy_current = rtpproxy_list;
  }
}

void pbx_media_proxy_init(void) {
  parse_rtpproxy_config();
}

void pbx_media_proxy_shutdown(void) {
  if (client_fd >= 0) {
    close(client_fd);
    client_fd = -1;
  }
  connected = 0;

  if (rtpproxy_list) {
    rtpproxy_node_t *node = rtpproxy_list;
    do {
      rtpproxy_node_t *next = node->next;
      if (node->parsed) parsed_url_free(node->parsed);
      free(node->url);
      free(node);
      node = next;
    } while (node && node != rtpproxy_list);
    rtpproxy_list = NULL;
    rtpproxy_current = NULL;
  }
}

bool pbx_media_proxy_connect(void) {
  if (connected && client_fd >= 0) return true;

  int max_attempts = 4;
  int attempts = 0;
  while (attempts < max_attempts) {
    if (!rtpproxy_current) {
      if (parse_rtpproxy_config() != 0) return false;
    }

    client_fd = connect_to_url(rtpproxy_current->parsed);
    if (client_fd >= 0) {
      connected = 1;
      log_info("pbx: connected to rtpproxy at %s", rtpproxy_current->url);
      return true;
    }

    log_warn("pbx: failed to connect to rtpproxy at %s, trying next", rtpproxy_current->url);
    switch_to_next_rtpproxy();
    attempts++;
  }

  log_error("pbx: failed to connect to any rtpproxy");
  return false;
}

void pbx_media_proxy_disconnect(void) {
  if (client_fd >= 0) {
    close(client_fd);
    client_fd = -1;
  }
  connected = 0;
  switch_to_next_rtpproxy();
}

static int send_command(int fd, const char *cmd, ...) {
  va_list args;
  va_start(args, cmd);

  resp_object *arr = resp_array_init();
  resp_array_append_bulk(arr, cmd);

  const char *arg;
  while ((arg = va_arg(args, const char *)) != NULL) {
    resp_array_append_bulk(arr, arg);
  }
  va_end(args);

  char *buf = NULL;
  size_t len = 0;
  resp_serialize(arr, &buf, &len);
  resp_free(arr);

  if (!buf) return -1;

  ssize_t written = write(fd, buf, len);
  free(buf);

  if (written < 0) return -1;
  return 0;
}

static resp_object *read_response(int fd) {
  char buf[4096];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  if (n <= 0) return NULL;
  buf[n] = '\0';

  resp_object *obj = NULL;
  if (resp_read_buf(buf, n, &obj) > 0 && obj) {
    return obj;
  }
  return NULL;
}

int pbx_media_proxy_session_create(const char *session_id) {
  if (!pbx_media_proxy_connect()) return -1;

  if (send_command(client_fd, "session.create", session_id, "3600", NULL) < 0) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  resp_object *resp = read_response(client_fd);
  if (!resp) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  int result = resp->type == RESPT_ARRAY ? 0 : -1;
  resp_free(resp);
  return result;
}

int pbx_media_proxy_session_destroy(const char *session_id) {
  if (!connected || client_fd < 0) return 0;

  if (send_command(client_fd, "session.destroy", session_id, NULL) < 0) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  resp_object *resp = read_response(client_fd);
  if (resp) {
    resp_free(resp);
  }
  return 0;
}

int pbx_media_proxy_create_listen_socket(const char *session_id, const char *socket_id, pbx_media_proxy_socket_info_t *info) {
  if (!connected) {
    if (!pbx_media_proxy_connect()) return -1;
  }

  if (send_command(client_fd, "session.socket.create.listen", session_id, socket_id, NULL) < 0) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  resp_object *resp = read_response(client_fd);
  if (!resp || resp->type != RESPT_ARRAY || resp->u.arr.n < 2) {
    if (resp) resp_free(resp);
    pbx_media_proxy_disconnect();
    return -1;
  }

  const char *port_str = resp_map_get_string(&resp->u.arr.elem[0], "_value");
  const char *adv_str = resp_map_get_string(&resp->u.arr.elem[1], "_value");

  if (info) {
    info->port = port_str ? atoi(port_str) : 0;
    if (adv_str) {
      strncpy(info->advertise_addr, adv_str, sizeof(info->advertise_addr) - 1);
    } else {
      info->advertise_addr[0] = '\0';
    }
  }

  resp_free(resp);
  return 0;
}

int pbx_media_proxy_create_connect_socket(const char *session_id, const char *socket_id, const char *ip, int port) {
  if (!connected) {
    if (!pbx_media_proxy_connect()) return -1;
  }

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  if (send_command(client_fd, "session.socket.create.connect", session_id, socket_id, ip, port_str, NULL) < 0) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  resp_object *resp = read_response(client_fd);
  if (!resp) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  int result = resp->type == RESPT_ARRAY ? 0 : -1;
  resp_free(resp);
  return result;
}

int pbx_media_proxy_create_forward(const char *session_id, const char *src_socket_id, const char *dst_socket_id) {
  if (!connected) {
    if (!pbx_media_proxy_connect()) return -1;
  }

  if (send_command(client_fd, "session.forward.create", session_id, src_socket_id, dst_socket_id, NULL) < 0) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  resp_object *resp = read_response(client_fd);
  if (!resp) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  int result = resp->type == RESPT_ARRAY ? 0 : -1;
  resp_free(resp);
  return result;
}
