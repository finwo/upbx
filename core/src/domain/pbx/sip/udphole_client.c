#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "rxi/log.h"
#include "infrastructure/config.h"
#include "common/resp.h"
#include "domain/pbx/sip/udphole_client.h"

static udphole_client_t *global_client = NULL;
static char *advertise_addr = NULL;
static char *auth_username = NULL;
static char *auth_password = NULL;

static int parse_url(udphole_client_t *client, const char *url) {
  if (!client || !url) return -1;

  client->address = strdup(url);
  if (!client->address) return -1;

  return 0;
}

int udphole_client_init(udphole_client_t *client, const char *address) {
  if (!client || !address) return -1;

  memset(client, 0, sizeof(*client));
  client->fd = -1;
  client->connected = 0;

  return parse_url(client, address);
}

void udphole_client_cleanup(udphole_client_t *client) {
  if (!client) return;

  udphole_client_disconnect(client);

  free(client->address);

  memset(client, 0, sizeof(*client));
  client->fd = -1;
}

static int resolve_host(const char *host, struct in_addr *addr) {
  if (!host || !addr) return -1;

  if (inet_pton(AF_INET, host, addr) > 0) {
    return 0;
  }

  struct hostent *he = gethostbyname(host);
  if (!he) return -1;

  memcpy(addr, he->h_addr_list[0], he->h_length);
  return 0;
}

int udphole_client_connect(udphole_client_t *client) {
  if (!client || client->connected) return 0;

  const char *url = client->address;
  if (!url) return -1;

  int sock = -1;

  if (strncmp(url, "tcp://", 6) == 0) {
    const char *path = url + 6;
    const char *colon = strchr(path, ':');
    if (!colon) {
      log_error("udphole: invalid tcp url, missing port");
      return -1;
    }

    char *host = strndup(path, colon - path);
    if (!host) return -1;

    int port = atoi(colon + 1);
    if (port <= 0) port = 12345;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      free(host);
      return -1;
    }

    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port = htons((uint16_t)port);

    if (resolve_host(host, &srv.sin_addr) < 0) {
      free(host);
      close(sock);
      return -1;
    }

    free(host);

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
      close(sock);
      return -1;
    }
  } else {
    log_error("udphole: unsupported url scheme: %s", url);
    return -1;
  }

  client->fd = sock;
  client->connected = 1;
  return 0;
}

void udphole_client_disconnect(udphole_client_t *client) {
  if (!client) return;

  if (client->fd >= 0) {
    close(client->fd);
    client->fd = -1;
  }
  client->connected = 0;
}

static int send_command(udphole_client_t *client, const char *cmd, size_t cmd_len) {
  if (!client || !client->connected || !cmd || cmd_len == 0) return -1;

  ssize_t sent = send(client->fd, cmd, cmd_len, 0);
  if (sent < 0) return -1;

  return 0;
}

static resp_object *read_response(udphole_client_t *client) {
  if (!client || !client->connected) return NULL;

  return resp_read(client->fd);
}

static int encode_and_send(udphole_client_t *client, int argc, const char **argv) {
  char *buf = NULL;
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

  int ret = send_command(client, buf, buf_len);
  free(buf);
  return ret;
}

int udphole_ping(udphole_client_t *client) {
  if (!client) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[1] = { "ping" };
  if (encode_and_send(client, 1, argv) < 0) return -1;

  resp_object *resp = read_response(client);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "PONG") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_session_create(udphole_client_t *client, const char *session_id, int idle_expiry) {
  if (!client || !session_id) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  char expiry_str[32];
  snprintf(expiry_str, sizeof(expiry_str), "%d", idle_expiry);

  const char *argv[3] = { "session.create", session_id, expiry_str };
  if (encode_and_send(client, 3, argv) < 0) return -1;

  resp_object *resp = read_response(client);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_session_destroy(udphole_client_t *client, const char *session_id) {
  if (!client || !session_id) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[2] = { "session.destroy", session_id };
  if (encode_and_send(client, 2, argv) < 0) return -1;

  resp_object *resp = read_response(client);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_socket_create_listen(udphole_client_t *client, const char *session_id, const char *socket_id, udphole_socket_info_t *info) {
  if (!client || !session_id || !socket_id || !info) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  memset(info, 0, sizeof(*info));

  const char *argv[3] = { "session.socket.create.listen", session_id, socket_id };
  if (encode_and_send(client, 3, argv) < 0) return -1;

  resp_object *resp = read_response(client);
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

int udphole_socket_create_connect(udphole_client_t *client, const char *session_id, const char *socket_id, const char *ip, int port, udphole_socket_info_t *info) {
  if (!client || !session_id || !socket_id || !ip || !info) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  memset(info, 0, sizeof(*info));

  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  const char *argv[5] = { "session.socket.create.connect", session_id, socket_id, ip, port_str };
  if (encode_and_send(client, 5, argv) < 0) return -1;

  resp_object *resp = read_response(client);
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

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[3] = { "session.socket.destroy", session_id, socket_id };
  if (encode_and_send(client, 3, argv) < 0) return -1;

  resp_object *resp = read_response(client);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_forward_create(udphole_client_t *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id) {
  if (!client || !session_id || !src_socket_id || !dst_socket_id) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[4] = { "session.forward.create", session_id, src_socket_id, dst_socket_id };
  if (encode_and_send(client, 4, argv) < 0) return -1;

  resp_object *resp = read_response(client);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_forward_destroy(udphole_client_t *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id) {
  if (!client || !session_id || !src_socket_id || !dst_socket_id) return -1;

  if (!client->connected) {
    if (udphole_client_connect(client) < 0) return -1;
  }

  const char *argv[4] = { "session.forward.destroy", session_id, src_socket_id, dst_socket_id };
  if (encode_and_send(client, 4, argv) < 0) return -1;

  resp_object *resp = read_response(client);
  if (!resp) return -1;

  int ok = (resp->type == RESPT_SIMPLE && resp->u.s && strcmp(resp->u.s, "OK") == 0);
  resp_free(resp);

  return ok ? 0 : -1;
}

int udphole_global_init(void) {
  if (global_client) return 0;

  const char *address = "tcp://127.0.0.1:12345";

  resp_object *udphole_sec = resp_map_get(global_cfg, "udphole");
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
      auth_username = strdup(user_cfg);
    }

    const char *pass_cfg = resp_map_get_string(udphole_sec, "password");
    if (pass_cfg && pass_cfg[0]) {
      auth_password = strdup(pass_cfg);
    }
  }

  global_client = (udphole_client_t *)malloc(sizeof(udphole_client_t));
  if (!global_client) return -1;

  if (udphole_client_init(global_client, address) < 0) {
    free(global_client);
    global_client = NULL;
    return -1;
  }

  if (udphole_client_connect(global_client) < 0) {
    log_error("udphole: failed to connect");
    udphole_client_cleanup(global_client);
    free(global_client);
    global_client = NULL;
    return -1;
  }

  if (auth_username && auth_password) {
    log_info("udphole: authenticating as %s", auth_username);
    const char *argv[3] = { "auth", auth_username, auth_password };
    if (encode_and_send(global_client, 3, argv) < 0) {
      log_error("udphole: failed to send auth command");
      udphole_client_disconnect(global_client);
      udphole_client_cleanup(global_client);
      free(global_client);
      global_client = NULL;
      return -1;
    }

    resp_object *resp = read_response(global_client);
    if (!resp || resp->type != RESPT_SIMPLE || !resp->u.s || strcmp(resp->u.s, "OK") != 0) {
      log_error("udphole: authentication failed");
      if (resp) resp_free(resp);
      udphole_client_disconnect(global_client);
      udphole_client_cleanup(global_client);
      free(global_client);
      global_client = NULL;
      return -1;
    }
    resp_free(resp);
    log_info("udphole: authenticated successfully");
  }

  log_info("udphole: initialized with address %s", address);

  return 0;
}

udphole_client_t *udphole_get_client(void) {
  return global_client;
}

const char *udphole_get_advertise_addr(void) {
  return advertise_addr;
}
