#include "infrastructure/udphole.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/resp.h"
#include "infrastructure/config.h"
#include "rxi/log.h"

typedef struct {
  int   fd;
  char *address;
  int   connected;
  char *auth_username;
  char *auth_password;
} udphole_impl_t;

static int impl_parse_url(udphole_impl_t *impl, const char *url) {
  if (!impl || !url) return -1;

  impl->address = strdup(url);
  if (!impl->address) return -1;

  return 0;
}

static int impl_connect_tcp(udphole_impl_t *impl) {
  const char *url = impl->address;
  if (!url) return -1;

  if (strncmp(url, "tcp://", 6) == 0) {
    const char *path  = url + 6;
    const char *colon = strchr(path, ':');
    if (!colon) {
      log_error("udphole: invalid tcp url, missing port");
      return -1;
    }

    char *host = strndup(path, colon - path);
    if (!host) return -1;

    int port = atoi(colon + 1);
    if (port <= 0) port = 12345;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      free(host);
      return -1;
    }

    struct sockaddr_in srv = {0};
    srv.sin_family         = AF_INET;
    srv.sin_port           = htons((uint16_t)port);

    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) > 0) {
      srv.sin_addr = addr;
    } else {
      struct hostent *he = gethostbyname(host);
      if (!he) {
        free(host);
        close(sock);
        return -1;
      }
      memcpy(&srv.sin_addr, he->h_addr_list[0], he->h_length);
    }

    free(host);

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
      close(sock);
      return -1;
    }

    impl->fd        = sock;
    impl->connected = 1;
    return 0;
  }

  log_error("udphole: unsupported url scheme: %s", url);
  return -1;
}

static int impl_connect_unix(udphole_impl_t *impl) {
  const char *url = impl->address;
  if (!url) return -1;

  if (strncmp(url, "unix://", 7) == 0) {
    const char *path = url + 7;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family         = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      close(sock);
      return -1;
    }

    impl->fd        = sock;
    impl->connected = 1;
    return 0;
  }

  log_error("udphole: unsupported url scheme: %s", url);
  return -1;
}

static int impl_connect(void *self) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl || impl->connected) return 0;

  if (strncmp(impl->address, "unix://", 7) == 0) {
    return impl_connect_unix(impl);
  }
  return impl_connect_tcp(impl);
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
  if (sent < 0) return -1;

  return 0;
}

static resp_object *impl_recv(void *self) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl || !impl->connected) return NULL;

  return resp_read(impl->fd);
}

static int impl_encode_and_send(udphole_impl_t *impl, int argc, const char **argv) {
  char  *buf     = NULL;
  size_t buf_len = 0;

  resp_object *args[16];
  for (int i = 0; i < argc && i < 16; i++) {
    args[i] = resp_array_init();
    if (!args[i]) return -1;
    resp_array_append_simple(args[i], argv[i]);
  }

  if (resp_encode_array(argc, (const resp_object *const *)args, &buf, &buf_len) != 0) {
    for (int i = 0; i < argc && i < 16; i++) {
      resp_free(args[i]);
    }
    return -1;
  }

  for (int i = 0; i < argc && i < 16; i++) {
    resp_free(args[i]);
  }

  int ret = impl_send(impl, buf, buf_len);
  free(buf);
  return ret;
}

static int impl_auth(void *self, const char *user, const char *pass) {
  udphole_impl_t *impl = (udphole_impl_t *)self;
  if (!impl || !impl->connected) return -1;

  const char *argv[3] = {"auth", user, pass};
  if (impl_encode_and_send(impl, 3, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

static void impl_cleanup(udphole_impl_t *impl) {
  if (!impl) return;

  impl_disconnect(impl);
  free(impl->address);
  free(impl->auth_username);
  free(impl->auth_password);

  memset(impl, 0, sizeof(*impl));
  impl->fd = -1;
}

static const udphole_transport_vtable impl_vtable = {
    .connect    = impl_connect,
    .disconnect = impl_disconnect,
    .send       = impl_send,
    .recv       = impl_recv,
    .auth       = impl_auth,
};

static udphole_client_t *global_client  = NULL;
static char             *advertise_addr = NULL;

int infrastructure_udphole_init_global(void) {
  if (global_client) return 0;

  const char *address   = "tcp://127.0.0.1:12345";
  const char *auth_user = NULL;
  const char *auth_pass = NULL;

  resp_object *udphole_sec = resp_map_get(domain_cfg, "udphole");
  if (udphole_sec) {
    const char *addr_cfg = resp_map_get_string(udphole_sec, "address");
    if (addr_cfg && addr_cfg[0]) {
      address = addr_cfg;
    }

    const char *adv_cfg = resp_map_get_string(udphole_sec, "advertise");
    if (adv_cfg && adv_cfg[0]) {
      advertise_addr = strdup(adv_cfg);
    }

    const char *user_cfg = resp_map_get_string(udphole_sec, "username");
    if (user_cfg && user_cfg[0]) {
      auth_user = user_cfg;
    }

    const char *pass_cfg = resp_map_get_string(udphole_sec, "password");
    if (pass_cfg && pass_cfg[0]) {
      auth_pass = pass_cfg;
    }
  }

  global_client = infrastructure_udphole_create(address, auth_user, auth_pass);
  if (!global_client) return -1;

  if (udphole_client_connect(global_client) < 0) {
    log_error("udphole: failed to connect");
    infrastructure_udphole_destroy(global_client);
    global_client = NULL;
    return -1;
  }

  if (auth_user && auth_pass) {
    log_info("udphole: authenticating as %s", auth_user);
    if (global_client->transport.vtable->auth(global_client->transport.impl, auth_user, auth_pass) < 0) {
      log_error("udphole: authentication failed");
      infrastructure_udphole_destroy(global_client);
      global_client = NULL;
      return -1;
    }
    log_info("udphole: authenticated successfully");
  }

  log_info("udphole: initialized with address %s", address);

  return 0;
}

void infrastructure_udphole_cleanup_global(void) {
  if (global_client) {
    infrastructure_udphole_destroy(global_client);
    global_client = NULL;
  }
  free(advertise_addr);
  advertise_addr = NULL;
}

udphole_client_t *infrastructure_udphole_create(const char *address, const char *auth_user, const char *auth_pass) {
  udphole_impl_t *impl = calloc(1, sizeof(udphole_impl_t));
  if (!impl) return NULL;

  impl->fd = -1;
  impl_parse_url(impl, address);

  if (auth_user) impl->auth_username = strdup(auth_user);
  if (auth_pass) impl->auth_password = strdup(auth_pass);

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
  if (!client) return -1;

  if (!((udphole_impl_t *)client->transport.impl)->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char     *argv[1] = {"ping"};
  udphole_impl_t *impl    = client->transport.impl;
  if (impl_encode_and_send(impl, 1, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "PONG") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_session_create(udphole_client_t *client, const char *session_id, int idle_expiry) {
  if (!client || !session_id) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  char expiry_str[32];
  snprintf(expiry_str, sizeof(expiry_str), "%d", idle_expiry);

  const char *argv[3] = {"session.create", session_id, expiry_str};
  if (impl_encode_and_send(impl, 3, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_session_destroy(udphole_client_t *client, const char *session_id) {
  if (!client || !session_id) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[2] = {"session.destroy", session_id};
  if (impl_encode_and_send(impl, 2, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_socket_create_listen(udphole_client_t *client, const char *session_id, const char *socket_id,
                                 udphole_socket_info_t *info) {
  if (!client || !session_id || !socket_id || !info) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  memset(info, 0, sizeof(*info));

  const char *argv[3] = {"session.socket.create.listen", session_id, socket_id};
  if (impl_encode_and_send(impl, 3, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
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
  if (!client || !session_id || !socket_id || !ip || !info) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  memset(info, 0, sizeof(*info));

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  const char *argv[5] = {"session.socket.create.connect", session_id, socket_id, ip, port_str};
  if (impl_encode_and_send(impl, 5, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
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
  if (!client || !session_id || !socket_id) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[3] = {"session.socket.destroy", session_id, socket_id};
  if (impl_encode_and_send(impl, 3, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_forward_create(udphole_client_t *client, const char *session_id, const char *src_socket_id,
                           const char *dst_socket_id) {
  if (!client || !session_id || !src_socket_id || !dst_socket_id) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[4] = {"session.forward.create", session_id, src_socket_id, dst_socket_id};
  if (impl_encode_and_send(impl, 4, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_forward_destroy(udphole_client_t *client, const char *session_id, const char *src_socket_id,
                            const char *dst_socket_id) {
  if (!client || !session_id || !src_socket_id || !dst_socket_id) return -1;

  udphole_impl_t *impl = client->transport.impl;
  if (!impl->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[4] = {"session.forward.destroy", session_id, src_socket_id, dst_socket_id};
  if (impl_encode_and_send(impl, 4, argv) < 0) return -1;

  resp_object *resp = impl_recv(impl);
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
  return global_client;
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
