#include "domain/pbx/media_proxy.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

static int authenticate_rtpproxy(int fd, struct parsed_url *parsed);

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
    log_debug("pbx: parse_rtpproxy_config - elem[%zu] type=%d", i, rtpproxies->u.arr.elem[i].type);
    const char *url = NULL;
    if (rtpproxies->u.arr.elem[i].type == RESPT_SIMPLE) {
      url = rtpproxies->u.arr.elem[i].u.s;
    } else if (rtpproxies->u.arr.elem[i].type == RESPT_BULK) {
      url = rtpproxies->u.arr.elem[i].u.s;
    }
    log_debug("pbx: parse_rtpproxy_config - elem[%zu] url=%s", i, url ? url : "(null)");
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
    log_debug("pbx: parse_rtpproxy_config - head=%p tail=%p", head, tail);
    tail->next = head;
    head->prev = tail;
    rtpproxy_list = head;
    rtpproxy_current = head;
    return 0;
  }

  log_error("pbx: parse_rtpproxy_config - head=%p tail=%p", head, tail);
  return -1;
}

static int connect_to_url(struct parsed_url *parsed) {
  if (!parsed || !parsed->scheme) {
    log_error("connect_to_url - parsed=%p scheme=%p", parsed, parsed ? parsed->scheme : NULL);
    return -1;
  }

  log_debug("connect_to_url - scheme=%s host=%s port=%s path=%s",
    parsed->scheme ? parsed->scheme : "(null)",
    parsed->host ? parsed->host : "(null)",
    parsed->port ? parsed->port : "(null)",
    parsed->path ? parsed->path : "(null)");

  if (strcmp(parsed->scheme, "unix") == 0) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
      log_error("connect_to_url - socket unix failed");
      return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const char *sock_path = parsed->path && parsed->path[0] ? parsed->path : parsed->host;
    if (!sock_path || !sock_path[0]) {
      log_error("connect_to_url - no socket path for unix scheme");
      close(fd);
      return -1;
    }
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      log_error("connect_to_url - unix connect failed: %s", strerror(errno));
      close(fd);
      return -1;
    }
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    return fd;
  }

  if (!parsed->host) {
    log_error("connect_to_url - no host for scheme %s", parsed->scheme);
    return -1;
  }

  int port = parsed->port ? atoi(parsed->port) : 6379;
  log_debug("connect_to_url - tcp connect to host=%s port=%d", parsed->host, port);

  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  int gai_err = getaddrinfo(parsed->host, port_str, &hints, &res);
  if (gai_err != 0 || !res) {
    log_error("connect_to_url - getaddrinfo failed: %s", gai_err ? gai_strerror(gai_err) : "no result");
    if (res) freeaddrinfo(res);
    return -1;
  }

  int fd = socket(res->ai_family, SOCK_STREAM, 0);
  if (fd < 0) {
    log_error("connect_to_url - socket failed: %s", strerror(errno));
    freeaddrinfo(res);
    return -1;
  }

  int conn_err = connect(fd, res->ai_addr, res->ai_addrlen);
  if (conn_err < 0) {
    log_error("connect_to_url - connect failed: %s", strerror(errno));
    freeaddrinfo(res);
    close(fd);
    return -1;
  }
  freeaddrinfo(res);

  int nodelay = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

  log_debug("connect_to_url - connected successfully");
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

  log_debug("pbx: media_proxy_connect - rtpproxy_current=%p", rtpproxy_current);

  if (!rtpproxy_current) {
    log_debug("pbx: media_proxy_connect - calling parse_rtpproxy_config");
    if (parse_rtpproxy_config() != 0) {
      log_error("pbx: media_proxy_connect - parse_rtpproxy_config failed");
      return false;
    }
  }

  if (!rtpproxy_current) {
    log_error("pbx: media_proxy_connect - no rtpproxies configured");
    return false;
  }

  rtpproxy_node_t *start = rtpproxy_current;
  do {
    if (rtpproxy_current) {
      log_debug("pbx: media_proxy_connect - url=%s", rtpproxy_current->url);
    }

    client_fd = connect_to_url(rtpproxy_current->parsed);
    if (client_fd >= 0) {
      if (authenticate_rtpproxy(client_fd, rtpproxy_current->parsed) != 0) {
        log_warn("pbx: failed to authenticate to rtpproxy at %s, trying next", rtpproxy_current->url);
        close(client_fd);
        client_fd = -1;
        switch_to_next_rtpproxy();
        continue;
      }
      connected = 1;
      log_info("pbx: connected to rtpproxy at %s", rtpproxy_current->url);
      return true;
    }

    log_warn("pbx: failed to connect to rtpproxy at %s, trying next", rtpproxy_current->url);
    switch_to_next_rtpproxy();
  } while (rtpproxy_current && rtpproxy_current != start);

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
  log_debug("read_response - n=%zd", n);
  if (n <= 0) {
    log_error("read_response - no data or error");
    return NULL;
  }
  buf[n] = '\0';
  log_debug("read_response - raw: %s", buf);

  resp_object *obj = NULL;
  if (resp_read_buf(buf, n, &obj) > 0 && obj) {
    char *ser = NULL;
    size_t ser_len = 0;
    resp_serialize(obj, &ser, &ser_len);
    log_debug("read_response - parsed: %s", ser ? ser : "(null)");
    free(ser);
    return obj;
  }
  log_error("read_response - failed to parse");
  return NULL;
}

static int authenticate_rtpproxy(int fd, struct parsed_url *parsed) {
  if (!parsed->username || !parsed->password) {
    return 0;
  }

  if (send_command(fd, "auth", parsed->username, parsed->password, NULL) < 0) {
    return -1;
  }

  resp_object *resp = read_response(fd);
  if (!resp) {
    return -1;
  }

  int result = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0) ? 0 : -1;
  resp_free(resp);
  return result;
}

static resp_object *pool_command(const char *cmd, ...) {
  if (!connected || client_fd < 0) {
    if (!pbx_media_proxy_connect()) {
      log_error("pbx: pool_command - failed to connect");
      return NULL;
    }
  }

  rtpproxy_node_t *start = rtpproxy_current;

  int count = 0;
  rtpproxy_node_t *tmp = rtpproxy_list;
  while (tmp) {
    count++;
    tmp = tmp->next;
    if (tmp == rtpproxy_list) break;
  }

  int attempt = 0;
  while (attempt < count) {
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

    if (!buf) return NULL;

    log_debug("pbx: pool_command - sending cmd=%s len=%zu", cmd, len);
    ssize_t written = write(client_fd, buf, len);
    log_debug("pbx: pool_command - written=%zd", written);
    free(buf);

    if (written < 0) {
      log_warn("pbx: pool_command - write failed, trying next rtpproxy");
      pbx_media_proxy_disconnect();
      if (!pbx_media_proxy_connect()) {
        return NULL;
      }
      if (rtpproxy_current == start) {
        attempt++;
      }
      continue;
    }

    log_debug("pbx: pool_command - reading response");
    resp_object *resp = read_response(client_fd);
    log_debug("pbx: pool_command - resp=%p", resp);
    if (!resp) {
      log_warn("pbx: pool_command - read response failed, trying next rtpproxy");
      pbx_media_proxy_disconnect();
      if (!pbx_media_proxy_connect()) {
        return NULL;
      }
      if (rtpproxy_current == start) {
        attempt++;
      }
      continue;
    }

    return resp;
  }

  log_error("pbx: pool_command - failed after retries");
  return NULL;
}

int pbx_media_proxy_session_create(const char *session_id) {
  log_debug("pbx: media_proxy_session_create - session_id=%s", session_id);
  if (!pbx_media_proxy_connect()) {
    log_error("pbx: media_proxy_session_create - failed to connect");
    return -1;
  }
  log_debug("pbx: media_proxy_session_create - connected, sending session.create");

  resp_object *resp = pool_command("session.create", session_id, "3600", NULL);
  log_debug("pbx: media_proxy_session_create - resp=%p", resp);
  if (!resp) {
    log_error("pbx: media_proxy_session_create - pool_command returned NULL");
    pbx_media_proxy_disconnect();
    return -1;
  }

  log_debug("pbx: media_proxy_session_create - resp->type=%d", resp->type);
  int result = resp->type == RESPT_SIMPLE ? 0 : -1;
  resp_free(resp);
  return result;
}

int pbx_media_proxy_session_destroy(const char *session_id) {
  if (!connected || client_fd < 0) return 0;

  resp_object *resp = pool_command("session.destroy", session_id, NULL);
  if (!resp) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  resp_free(resp);
  return 0;
}

int pbx_media_proxy_create_listen_socket(const char *session_id, const char *socket_id, pbx_media_proxy_socket_info_t *info) {
  log_debug("pbx: media_proxy create listen socket session=%s id=%s", session_id, socket_id);
  resp_object *resp = pool_command("session.socket.create.listen", session_id, socket_id, NULL);
  log_debug("pbx: media_proxy resp=%p type=%d n=%zu", (void*)resp, resp ? resp->type : -1, resp && resp->type == RESPT_ARRAY ? resp->u.arr.n : 0);
  if (!resp || resp->type != RESPT_ARRAY || resp->u.arr.n < 1) {
    if (resp) resp_free(resp);
    pbx_media_proxy_disconnect();
    return -1;
  }

  int port = 0;
  const char *adv_str = NULL;

  if (resp->u.arr.n >= 1) {
    resp_object *port_elem = &resp->u.arr.elem[0];
    if (port_elem->type == RESPT_INT) {
      port = port_elem->u.i;
    } else if (port_elem->type == RESPT_SIMPLE) {
      port = atoi(port_elem->u.s);
    }
  }

  if (resp->u.arr.n >= 2) {
    resp_object *adv_elem = &resp->u.arr.elem[1];
    if (adv_elem->type == RESPT_SIMPLE) {
      adv_str = adv_elem->u.s;
    } else if (adv_elem->type == RESPT_BULK) {
      adv_str = adv_elem->u.s;
    }
  }

  log_debug("pbx: media_proxy port=%d adv_str=%s", port, adv_str ? adv_str : "null");

  if (info) {
    info->port = port;
    if (adv_str && adv_str[0]) {
      strncpy(info->advertise_addr, adv_str, sizeof(info->advertise_addr) - 1);
    } else {
      info->advertise_addr[0] = '\0';
    }
  }

  resp_free(resp);
  return 0;
}

int pbx_media_proxy_create_connect_socket(const char *session_id, const char *socket_id, const char *ip, int port) {
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  resp_object *resp = pool_command("session.socket.create.connect", session_id, socket_id, ip, port_str, NULL);
  if (!resp) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  int result = resp->type == RESPT_ARRAY ? 0 : -1;
  resp_free(resp);
  return result;
}

int pbx_media_proxy_create_forward(const char *session_id, const char *src_socket_id, const char *dst_socket_id) {
  resp_object *resp = pool_command("session.forward.create", session_id, src_socket_id, dst_socket_id, NULL);
  if (!resp) {
    pbx_media_proxy_disconnect();
    return -1;
  }

  int result = resp->type == RESPT_ARRAY ? 0 : -1;
  resp_free(resp);
  return result;
}
