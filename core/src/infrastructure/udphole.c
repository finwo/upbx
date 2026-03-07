#include "infrastructure/udphole.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/resp.h"
#include "finwo/url-parser.h"
#include "infrastructure/config.h"
#include "rxi/log.h"

typedef struct {
  int   fd;
  char *url;
  int   connected;
} udphole_impl_t;

static void impl_parse_url(udphole_impl_t *impl, const char *url);
static void impl_disconnect(void *self);
static int impl_send(void *self, const char *cmd, size_t cmd_len);
static resp_object *impl_recv(void *self);

static void impl_parse_url(udphole_impl_t *impl, const char *url) {
  free(impl->url);
  impl->url = url ? strdup(url) : NULL;
}

static int impl_connect(void *self) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl || impl->connected || !impl->url) return 0;

  struct parsed_url *parsed = parse_url(impl->url);
  if (!parsed || !parsed->scheme) {
    if (parsed) parsed_url_free(parsed);
    return -1;
  }

  int sock;
  if (strcmp(parsed->scheme, "unix") == 0) {
    if (!parsed->path) {
      parsed_url_free(parsed);
      return -1;
    }
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      parsed_url_free(parsed);
      return -1;
    }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, parsed->path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      close(sock);
      parsed_url_free(parsed);
      return -1;
    }
  } else {
    if (!parsed->host) {
      parsed_url_free(parsed);
      return -1;
    }
    const char *port = parsed->port ? parsed->port : "12345";
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      parsed_url_free(parsed);
      return -1;
    }
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port = htons((uint16_t)atoi(port));
    struct in_addr addr;
    if (inet_pton(AF_INET, parsed->host, &addr) > 0) {
      srv.sin_addr = addr;
    } else {
      struct hostent *he = gethostbyname(parsed->host);
      if (!he) {
        close(sock);
        parsed_url_free(parsed);
        return -1;
      }
      memcpy(&srv.sin_addr, he->h_addr_list[0], he->h_length);
    }
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
      log_warn("udphole: connect() failed: %m");
      close(sock);
      parsed_url_free(parsed);
      return -1;
    }
    log_info("udphole: connected, now authenticating");
  }

  impl->fd = sock;
  impl->connected = 1;

  if (parsed->username && parsed->password) {
    log_info("udphole: sending auth command");
    resp_object *cmd = resp_array_init();
    resp_array_append_bulk(cmd, "auth");
    resp_array_append_bulk(cmd, parsed->username);
    resp_array_append_bulk(cmd, parsed->password);
    char *buf = NULL;
    size_t buf_len = 0;
    resp_serialize(cmd, &buf, &buf_len);
    resp_free(cmd);

    if (impl_send(impl, buf, buf_len) < 0) {
      free(buf);
      impl_disconnect(impl);
      parsed_url_free(parsed);
      return -1;
    }
    free(buf);

    resp_object *resp = impl_recv(impl);
    if (!resp) {
      log_warn("udphole: auth response is NULL");
      impl_disconnect(impl);
      parsed_url_free(parsed);
      return -1;
    }
    log_info("udphole: auth response received, type=%d", resp->type);
    if (resp->type != RESPT_SIMPLE || !resp->u.s || strcmp(resp->u.s, "OK") != 0) {
      log_warn("udphole: auth failed, response=%s", resp->u.s ? resp->u.s : "(null)");
      resp_free(resp);
      impl_disconnect(impl);
      parsed_url_free(parsed);
      return -1;
    }
    log_info("udphole: auth succeeded");
    resp_free(resp);
  }

  parsed_url_free(parsed);
  return 0;
}

static void impl_disconnect(void *self) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl) return;

  if (impl->fd >= 0) {
    close(impl->fd);
    impl->fd = -1;
  }
  impl->connected = 0;
}

static int impl_send(void *self, const char *cmd, size_t cmd_len) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl || !impl->connected || !cmd || cmd_len == 0) return -1;

  ssize_t sent = send(impl->fd, cmd, cmd_len, 0);
  if (sent < 0) {
    return -1;
  }

  return 0;
}

static resp_object *impl_recv(void *self) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl || !impl->connected) return NULL;

  return resp_read(impl->fd);
}

static void impl_cleanup(udphole_impl_t *impl) {
  if (!impl) return;

  impl_disconnect(impl);
  free(impl->url);

  memset(impl, 0, sizeof(*impl));
  impl->fd = -1;
}

static const udphole_transport_vtable impl_vtable = {
    .connect    = impl_connect,
    .disconnect = impl_disconnect,
    .send       = impl_send,
    .recv       = impl_recv,
};

static char             *advertise_addr = NULL;
static rtpproxy_pool_t  *global_pool    = NULL;

int infrastructure_udphole_init_global(void) {
  if (global_pool) return 0;

  resp_object *upbx_sec = resp_map_get(domain_cfg, "upbx");
  resp_object *rtp_arr = upbx_sec ? resp_map_get(upbx_sec, "rtpproxy") : NULL;

  if (!rtp_arr || rtp_arr->type != RESPT_ARRAY || rtp_arr->u.arr.n == 0) {
    log_fatal("udphole: no rtpproxy configured");
    return -1;
  }

  rtpproxy_node_t *head = NULL;
  rtpproxy_node_t *prev = NULL;

  for (size_t i = 0; i < rtp_arr->u.arr.n; i++) {
    const char *url = rtp_arr->u.arr.elem[i].u.s;
    if (!url || !url[0]) continue;

    udphole_client_t *client = infrastructure_udphole_create(url, NULL, NULL);
    if (!client) continue;

    rtpproxy_node_t *node = malloc(sizeof(rtpproxy_node_t));
    if (!node) {
      infrastructure_udphole_destroy(client);
      continue;
    }
    node->client = client;
    node->next = NULL;

    if (!head) {
      head = node;
    } else {
      prev->next = node;
    }
    prev = node;
  }

  if (!head) {
    log_fatal("udphole: could not create any rtpproxy client");
    return -1;
  }

  prev->next = head;

  global_pool = malloc(sizeof(rtpproxy_pool_t));
  if (!global_pool) {
    rtpproxy_node_t *node = head;
    while (node) {
      rtpproxy_node_t *next = node->next;
      infrastructure_udphole_destroy(node->client);
      free(node);
      if (node == head) break;
      node = next;
    }
    log_fatal("udphole: could not allocate rtpproxy pool");
    return -1;
  }

  global_pool->head = head;
  global_pool->current = head;
  global_pool->count = 0;

  rtpproxy_node_t *node = head;
  do {
    global_pool->count++;
    node = node->next;
  } while (node && node != head);

  log_info("udphole: initialized with %d rtpproxy(s) configured", global_pool->count);

  rtpproxy_node_t *start = head;
  do {
    log_info("udphole: connection attempt to %s", ((udphole_impl_t *)global_pool->current->client->transport.impl)->url);
    if (udphole_client_connect(global_pool->current->client) == 0) {
      log_info("udphole: connected to %s", ((udphole_impl_t *)global_pool->current->client->transport.impl)->url);
      break;
    }
    log_warn("udphole: failed to connect to %s, will retry later", ((udphole_impl_t *)global_pool->current->client->transport.impl)->url);
    global_pool->current = global_pool->current->next;
  } while (global_pool->current != start);

  return 0;
}

void infrastructure_udphole_cleanup_global(void) {
  if (global_pool) {
    rtpproxy_node_t *node = global_pool->head;
    do {
      rtpproxy_node_t *next = node->next;
      infrastructure_udphole_destroy(node->client);
      free(node);
      if (node == global_pool->head) break;
      node = next;
    } while (node);
    free(global_pool);
    global_pool = NULL;
  }
  free(advertise_addr);
  advertise_addr = NULL;
}

static int pool_advance(void) {
  if (!global_pool || global_pool->count <= 1) return -1;

  rtpproxy_node_t *start = global_pool->current;
  global_pool->current = global_pool->current->next;

  do {
    udphole_client_t *client = global_pool->current->client;
    if (((udphole_impl_t *)client->transport.impl)->connected ||
        udphole_client_connect(client) == 0) {
      return 0;
    }
    log_warn("udphole: failed to use %s, trying next", ((udphole_impl_t *)client->transport.impl)->url);
    global_pool->current = global_pool->current->next;
  } while (global_pool->current != start);

  return -1;
}

static resp_object *pool_execute(resp_object *cmd) {
  if (!global_pool || !cmd) return NULL;

  char *buf = NULL;
  size_t buf_len = 0;
  if (resp_serialize(cmd, &buf, &buf_len) != 0) {
    return NULL;
  }

  for (int i = 0; i < global_pool->count; i++) {
    udphole_client_t *client = global_pool->current->client;
    udphole_impl_t *impl = client->transport.impl;

    if (!impl->connected) {
      if (udphole_client_connect(client) < 0) {
        pool_advance();
        continue;
      }
    }

    if (impl_send(impl, buf, buf_len) < 0) {
      udphole_client_disconnect(client);
      pool_advance();
      continue;
    }

    resp_object *resp = impl_recv(impl);
    if (!resp) {
      udphole_client_disconnect(client);
      pool_advance();
      continue;
    }

    free(buf);
    return resp;
  }

  free(buf);
  return NULL;
}

udphole_client_t *infrastructure_udphole_create(const char *address, const char *auth_user, const char *auth_pass) {
  (void)auth_user;
  (void)auth_pass;
  udphole_impl_t *impl = calloc(1, sizeof(udphole_impl_t));
  if (!impl) return NULL;

  impl->fd = -1;
  impl_parse_url(impl, address);

  udphole_client_t *client = calloc(1, sizeof(udphole_client_t));
  if (!client) {
    impl_cleanup(impl);
    free(impl);
    return NULL;
  }

  client->transport.vtable = &impl_vtable;
  client->transport.impl   = impl;

  return client;
}

void infrastructure_udphole_destroy(udphole_client_t *client) {
  if (!client) return;

  if (client->transport.impl) {
    udphole_impl_t *impl = (udphole_impl_t *)client->transport.impl;
    impl_cleanup(impl);
    free(impl);
  }

  free(client->advertise_ip);
  free(client);
}

int udphole_client_connect(udphole_client_t *client) {
  if (!client) return -1;
  return client->transport.vtable->connect(client->transport.impl);
}

void udphole_client_disconnect(udphole_client_t *client) {
  if (!client) return;
  client->transport.vtable->disconnect(client->transport.impl);
}

int udphole_ping(udphole_client_t *client) {
  (void)client;
  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "ping");

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  char * serialized = NULL;
  size_t serialized_len = 0;
  resp_serialize(resp, &serialized, &serialized_len);
  log_debug("udphole_ping response: %s", serialized ? serialized : "(null)");
  free(serialized);

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "PONG") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_session_create(udphole_client_t *client, const char *session_id, int idle_expiry) {
  (void)client;
  if (!session_id) return -1;

  char expiry_str[32];
  snprintf(expiry_str, sizeof(expiry_str), "%d", idle_expiry);

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.create");
  resp_array_append_bulk(cmd, session_id);
  resp_array_append_bulk(cmd, expiry_str);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_session_destroy(udphole_client_t *client, const char *session_id) {
  (void)client;
  if (!session_id) return -1;

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.destroy");
  resp_array_append_bulk(cmd, session_id);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_socket_create_listen(udphole_client_t *client, const char *session_id, const char *socket_id,
                                 udphole_socket_info_t *info) {
  (void)client;
  if (!session_id || !socket_id || !info) return -1;

  memset(info, 0, sizeof(*info));

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.socket.create.listen");
  resp_array_append_bulk(cmd, session_id);
  resp_array_append_bulk(cmd, socket_id);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  if (resp->type != RESPT_ARRAY || resp->u.arr.n != 2) {
    resp_free(resp);
    return -1;
  }

  resp_object *port_obj = &resp->u.arr.elem[0];
  if (port_obj->type == RESPT_INT) {
    info->port = (int)port_obj->u.i;
  } else if (port_obj->type == RESPT_SIMPLE || port_obj->type == RESPT_BULK) {
    info->port = atoi(port_obj->u.s);
  }

  resp_object *ip_obj = &resp->u.arr.elem[1];
  if (ip_obj->type == RESPT_SIMPLE || ip_obj->type == RESPT_BULK) {
    info->advertise_ip = strdup(ip_obj->u.s);
  }

  resp_free(resp);
  return 0;
}

int udphole_socket_create_connect(udphole_client_t *client, const char *session_id, const char *socket_id,
                                  const char *ip, int port, udphole_socket_info_t *info) {
  (void)client;
  if (!session_id || !socket_id || !ip || !info) return -1;

  memset(info, 0, sizeof(*info));

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.socket.create.connect");
  resp_array_append_bulk(cmd, session_id);
  resp_array_append_bulk(cmd, socket_id);
  resp_array_append_bulk(cmd, ip);
  resp_array_append_bulk(cmd, port_str);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  if (resp->type != RESPT_ARRAY || resp->u.arr.n != 2) {
    resp_free(resp);
    return -1;
  }

  resp_object *port_obj = &resp->u.arr.elem[0];
  if (port_obj->type == RESPT_INT) {
    info->port = (int)port_obj->u.i;
  } else if (port_obj->type == RESPT_SIMPLE || port_obj->type == RESPT_BULK) {
    info->port = atoi(port_obj->u.s);
  }

  resp_object *ip_obj = &resp->u.arr.elem[1];
  if (ip_obj->type == RESPT_SIMPLE || ip_obj->type == RESPT_BULK) {
    info->advertise_ip = strdup(ip_obj->u.s);
  }

  resp_free(resp);
  return 0;
}

int udphole_socket_destroy(udphole_client_t *client, const char *session_id, const char *socket_id) {
  (void)client;
  if (!session_id || !socket_id) return -1;

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.socket.destroy");
  resp_array_append_bulk(cmd, session_id);
  resp_array_append_bulk(cmd, socket_id);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_forward_create(udphole_client_t *client, const char *session_id, const char *src_socket_id,
                           const char *dst_socket_id) {
  (void)client;
  if (!session_id || !src_socket_id || !dst_socket_id) return -1;

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.forward.create");
  resp_array_append_bulk(cmd, session_id);
  resp_array_append_bulk(cmd, src_socket_id);
  resp_array_append_bulk(cmd, dst_socket_id);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_forward_destroy(udphole_client_t *client, const char *session_id, const char *src_socket_id,
                            const char *dst_socket_id) {
  (void)client;
  if (!session_id || !src_socket_id || !dst_socket_id) return -1;

  resp_object *cmd = resp_array_init();
  resp_array_append_bulk(cmd, "session.forward.destroy");
  resp_array_append_bulk(cmd, session_id);
  resp_array_append_bulk(cmd, src_socket_id);
  resp_array_append_bulk(cmd, dst_socket_id);

  resp_object *resp = pool_execute(cmd);
  resp_free(cmd);

  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

void udphole_client_init_global(void) {
  infrastructure_udphole_init_global();
}

void udphole_client_cleanup_global(void) {
  infrastructure_udphole_cleanup_global();
}

udphole_client_t *udphole_get_client(void) {
  if (!global_pool || !global_pool->current) return NULL;
  return global_pool->current->client;
}

const char *udphole_get_advertise_addr(void) {
  return advertise_addr;
}

udphole_client_t *udphole_client_create(const char *address, const char *auth_user, const char *auth_pass) {
  return infrastructure_udphole_create(address, auth_user, auth_pass);
}

void udphole_client_destroy(udphole_client_t *client) {
  infrastructure_udphole_destroy(client);
}

#define UDPHOLE_KEEPALIVE_INTERVAL_MS 30000

typedef struct {
  int64_t last_ping;
} udphole_keepalive_udata_t;

int udphole_keepalive_pt(int64_t timestamp, struct pt_task *task) {
  udphole_keepalive_udata_t *udata = task->udata;

  if (!udata) {
    udata = calloc(1, sizeof(udphole_keepalive_udata_t));
    if (!udata) return SCHED_ERROR;
    udata->last_ping = timestamp;
    task->udata     = udata;
  }

  if (timestamp - udata->last_ping >= UDPHOLE_KEEPALIVE_INTERVAL_MS) {
    udata->last_ping = timestamp;

    udphole_client_t *client = udphole_get_client();
    if (!client) {
      log_warn("udphole: keepalive - no client available");
      return SCHED_RUNNING;
    }

    if (udphole_ping(client) == 0) {
      log_trace("udphole: keepalive ping successful");
    } else {
      log_warn("udphole: keepalive ping failed");
    }
  }

  return SCHED_RUNNING;
}
