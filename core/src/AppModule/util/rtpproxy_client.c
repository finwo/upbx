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
#include "config.h"
#include "RespModule/resp.h"
#include "AppModule/util/rtpproxy_client.h"

#define RTPP_DEFAULT_PORT 22222
#define RTPP_REPLY_BUF_SIZE 512

rtpp_client_t *rtpproxy_client = NULL;

static int parse_url(rtpp_client_t *client, const char *url) {
  if (!client || !url) return -1;

  client->url = strdup(url);
  if (!client->url) return -1;

  /* Handle URL schemes */
  if (strncmp(url, "unix://", 7) == 0) {
    client->type = RTPP_TYPE_UNIX;
    client->path = strdup(url + 7);
    client->host = NULL;
    client->port = 0;
  } else if (strncmp(url, "cunix://", 8) == 0) {
    client->type = RTPP_TYPE_CUNIX;
    client->path = strdup(url + 8);
    client->host = NULL;
    client->port = 0;
  } else if (strncmp(url, "tcp://", 6) == 0) {
    client->type = RTPP_TYPE_TCP;
    client->path = NULL;
    /* Parse host:port */
    const char *path = url + 6;
    const char *colon = strchr(path, ':');
    if (colon) {
      client->host = strndup(path, colon - path);
      client->port = atoi(colon + 1);
      if (client->port == 0) client->port = RTPP_DEFAULT_PORT;
    } else {
      client->host = strdup(path);
      client->port = RTPP_DEFAULT_PORT;
    }
  } else if (strncmp(url, "udp://", 6) == 0) {
    client->type = RTPP_TYPE_UDP;
    client->path = NULL;
    /* Parse host:port */
    const char *path = url + 6;
    const char *colon = strchr(path, ':');
    if (colon) {
      client->host = strndup(path, colon - path);
      client->port = atoi(colon + 1);
      if (client->port == 0) client->port = RTPP_DEFAULT_PORT;
    } else {
      client->host = strdup(path);
      client->port = RTPP_DEFAULT_PORT;
    }
  } else {
    /* Treat as unix socket path (backward compat: no prefix means unix) */
    client->type = RTPP_TYPE_UNIX;
    client->path = strdup(url);
    client->host = NULL;
    client->port = 0;
  }

  return 0;
}

int rtpp_client_init(rtpp_client_t *client, const char *url) {
  if (!client || !url) return -1;

  memset(client, 0, sizeof(*client));
  client->sockfd = -1;
  client->connected = 0;

  return parse_url(client, url);
}

void rtpp_client_cleanup(rtpp_client_t *client) {
  if (!client) return;

  rtpp_client_disconnect(client);

  free(client->url);
  free(client->path);
  free(client->host);

  memset(client, 0, sizeof(*client));
  client->sockfd = -1;
}

static int resolve_host(const char *host, struct in_addr *addr) {
  if (!host || !addr) return -1;

  if (inet_pton(AF_INET, host, addr) > 0) {
    return 0;  /* Successfully parsed as IP */
  }

  /* Try DNS resolution */
  struct hostent *he = gethostbyname(host);
  if (!he) return -1;

  memcpy(addr, he->h_addr_list[0], he->h_length);
  return 0;
}

int rtpp_client_connect(rtpp_client_t *client) {
  if (!client || client->connected) return 0;

  int sock = -1;

  switch (client->type) {
    case RTPP_TYPE_UNIX:
    case RTPP_TYPE_CUNIX: {
      sock = socket(AF_UNIX, SOCK_DGRAM, 0);
      if (sock < 0) return -1;
      break;
    }

    case RTPP_TYPE_TCP: {
      sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock < 0) return -1;

      struct sockaddr_in srv = {0};
      srv.sin_family = AF_INET;
      srv.sin_port = htons((uint16_t)client->port);

      if (resolve_host(client->host, &srv.sin_addr) < 0) {
        close(sock);
        return -1;
      }

      if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        close(sock);
        return -1;
      }
      break;
    }

    case RTPP_TYPE_UDP: {
      sock = socket(AF_INET, SOCK_DGRAM, 0);
      if (sock < 0) return -1;

      /* For UDP, we don't connect, but we set up for send/recv */
      break;
    }

    default:
      return -1;
  }

  client->sockfd = sock;
  client->connected = 1;
  return 0;
}

void rtpp_client_disconnect(rtpp_client_t *client) {
  if (!client) return;

  if (client->sockfd >= 0) {
    close(client->sockfd);
    client->sockfd = -1;
  }
  client->connected = 0;
}

int rtpp_client_send(rtpp_client_t *client, const char *cmd, size_t cmd_len) {
  if (!client || !client->connected || !cmd || cmd_len == 0) return -1;

  ssize_t sent = send(client->sockfd, cmd, cmd_len, 0);
  if (sent < 0) return -1;

  return 0;
}

int rtpp_client_recv(rtpp_client_t *client, char *reply, size_t reply_len) {
  if (!client || !client->connected || !reply || reply_len == 0) return -1;

  /* Read until newline (RTPP uses line-based responses) */
  size_t pos = 0;
  while (pos < reply_len - 1) {
    ssize_t n = recv(client->sockfd, reply + pos, 1, 0);
    if (n <= 0) return -1;
    if (reply[pos] == '\n') break;
    pos++;
  }
  reply[pos] = '\0';

  return (int)pos;
}

int rtpp_version(rtpp_client_t *client, char *version_out, size_t version_len) {
  if (!client || !version_out || version_len == 0) return -1;

  if (!client->connected) {
    if (rtpp_client_connect(client) < 0) return -1;
  }

  /* Send V command */
  if (rtpp_client_send(client, "V\n", 2) < 0) return -1;

  /* Read reply */
  char reply[RTPP_REPLY_BUF_SIZE];
  if (rtpp_client_recv(client, reply, sizeof(reply)) < 0) return -1;

  /* Reply should be version string like "20040107" */
  strncpy(version_out, reply, version_len - 1);
  version_out[version_len - 1] = '\0';

  return 0;
}

int rtpp_update(rtpp_client_t *client,
                const char *call_id,
                const char *remote_ip, int remote_port,
                const char *from_tag, const char *to_tag,
                const char *opts,
                int *out_port, char *out_ip, size_t out_ip_len) {
  if (!client || !call_id || !from_tag || !out_port) return -1;

  if (!client->connected) {
    if (rtpp_client_connect(client) < 0) return -1;
  }

  /* Build U command: U[opts] call_id remote_ip remote_port from_tag [to_tag] */
  char cmd[512];
  int len;

  if (to_tag && to_tag[0]) {
    if (opts && opts[0]) {
      len = snprintf(cmd, sizeof(cmd), "U%s %s %s %d %s %s\n",
                     opts, call_id, remote_ip, remote_port, from_tag, to_tag);
    } else {
      len = snprintf(cmd, sizeof(cmd), "U %s %s %d %s %s\n",
                     call_id, remote_ip, remote_port, from_tag, to_tag);
    }
  } else {
    if (opts && opts[0]) {
      len = snprintf(cmd, sizeof(cmd), "U%s %s %s %d %s\n",
                     opts, call_id, remote_ip, remote_port, from_tag);
    } else {
      len = snprintf(cmd, sizeof(cmd), "U %s %s %d %s\n",
                     call_id, remote_ip, remote_port, from_tag);
    }
  }

  if (len <= 0 || (size_t)len >= sizeof(cmd)) return -1;

  log_trace("rtpproxy: U cmd: %.200s", cmd);

  if (rtpp_client_send(client, cmd, (size_t)len) < 0) return -1;

  /* Read SOCKET_REPLY: port [ip] */
  char reply[RTPP_REPLY_BUF_SIZE];
  if (rtpp_client_recv(client, reply, sizeof(reply)) < 0) return -1;

  log_trace("rtpproxy: U reply: %.100s", reply);

  /* Parse reply: may be just port or "port ip" */
  *out_port = atoi(reply);

  if (out_ip && out_ip_len > 0) {
    out_ip[0] = '\0';
    /* Check if there's an IP address after the port */
    char *space = strchr(reply, ' ');
    if (space) {
      space++;
      while (*space == ' ' || *space == '\t') space++;
      char *end = space;
      while (*end && *end != '\n' && *end != '\r') end++;
      size_t ip_len = (size_t)(end - space);
      if (ip_len > 0 && ip_len < out_ip_len) {
        strncpy(out_ip, space, ip_len);
        out_ip[ip_len] = '\0';
      }
    }
  }

  if (*out_port <= 0) {
    /* Check for error */
    if (reply[0] == 'E') {
      log_error("rtpproxy: U command failed: %s", reply);
      return -1;
    }
  }

  return 0;
}

int rtpp_lookup(rtpp_client_t *client,
               const char *call_id,
               const char *remote_ip, int remote_port,
               const char *from_tag, const char *to_tag,
               const char *opts,
               int *out_port) {
  if (!client || !call_id || !remote_ip || !from_tag || !out_port) return -1;

  if (!client->connected) {
    if (rtpp_client_connect(client) < 0) return -1;
  }

  /* Build L command */
  char cmd[512];
  int len;

  if (to_tag && to_tag[0]) {
    if (opts && opts[0]) {
      len = snprintf(cmd, sizeof(cmd), "L%s %s %s %d %s %s\n",
                     opts, call_id, remote_ip, remote_port, from_tag, to_tag);
    } else {
      len = snprintf(cmd, sizeof(cmd), "L %s %s %d %s %s\n",
                     call_id, remote_ip, remote_port, from_tag, to_tag);
    }
  } else {
    if (opts && opts[0]) {
      len = snprintf(cmd, sizeof(cmd), "L%s %s %s %d %s\n",
                     opts, call_id, remote_ip, remote_port, from_tag);
    } else {
      len = snprintf(cmd, sizeof(cmd), "L %s %s %d %s\n",
                     call_id, remote_ip, remote_port, from_tag);
    }
  }

  if (len <= 0 || (size_t)len >= sizeof(cmd)) return -1;

  if (rtpp_client_send(client, cmd, (size_t)len) < 0) return -1;

  char reply[RTPP_REPLY_BUF_SIZE];
  if (rtpp_client_recv(client, reply, sizeof(reply)) < 0) return -1;

  *out_port = atoi(reply);

  if (*out_port <= 0 && reply[0] == 'E') {
    log_error("rtpproxy: L command failed: %s", reply);
    return -1;
  }

  return 0;
}

int rtpp_delete(rtpp_client_t *client,
                const char *call_id,
                const char *from_tag, const char *to_tag,
                int weak) {
  if (!client || !call_id || !from_tag) return -1;

  if (!client->connected) {
    if (rtpp_client_connect(client) < 0) return -1;
  }

  /* Build D command: D[w] call_id from_tag [to_tag] */
  char cmd[512];
  int len;

  if (to_tag && to_tag[0]) {
    len = snprintf(cmd, sizeof(cmd), "D%s %s %s %s\n",
                   weak ? "W" : "", call_id, from_tag, to_tag);
  } else {
    len = snprintf(cmd, sizeof(cmd), "D%s %s %s\n",
                   weak ? "W" : "", call_id, from_tag);
  }

  if (len <= 0 || (size_t)len >= sizeof(cmd)) return -1;

  if (rtpp_client_send(client, cmd, (size_t)len) < 0) return -1;

  char reply[RTPP_REPLY_BUF_SIZE];
  if (rtpp_client_recv(client, reply, sizeof(reply)) < 0) return -1;

  /* Reply should be "0" for success */
  if (reply[0] != '0') {
    log_error("rtpproxy: D command failed: %s", reply);
    return -1;
  }

  return 0;
}

int rtpp_query(rtpp_client_t *client,
               const char *call_id,
               const char *from_tag, const char *to_tag,
               int verbose,
               char *stats_out, size_t stats_len) {
  if (!client || !call_id || !from_tag || !stats_out || stats_len == 0) return -1;

  if (!client->connected) {
    if (rtpp_client_connect(client) < 0) return -1;
  }

  /* Build Q command: Q[v] call_id from_tag [to_tag] */
  char cmd[512];
  int len;

  if (to_tag && to_tag[0]) {
    len = snprintf(cmd, sizeof(cmd), "Q%s %s %s %s\n",
                   verbose ? "v" : "", call_id, from_tag, to_tag);
  } else {
    len = snprintf(cmd, sizeof(cmd), "Q%s %s %s\n",
                   verbose ? "v" : "", call_id, from_tag);
  }

  if (len <= 0 || (size_t)len >= sizeof(cmd)) return -1;

  if (rtpp_client_send(client, cmd, (size_t)len) < 0) return -1;

  char reply[RTPP_REPLY_BUF_SIZE];
  if (rtpp_client_recv(client, reply, sizeof(reply)) < 0) return -1;

  strncpy(stats_out, reply, stats_len - 1);
  stats_out[stats_len - 1] = '\0';

  return 0;
}

int rtpproxy_client_global_init(void) {
  if (rtpproxy_client) return 0;  /* Already initialized */

  const char *config_path = config_get_path();
  if (!config_path) return -1;

  static const char default_url[] = "unix:///var/run/upbx-rtpproxy.sock";

  resp_object *url_obj = config_key_get("rtpproxy", "url");
  char *url = NULL;
  if (url_obj && (url_obj->type == RESPT_BULK || url_obj->type == RESPT_SIMPLE) && url_obj->u.s && url_obj->u.s[0]) {
    url = strdup(url_obj->u.s);
    resp_free(url_obj);
  } else {
    url = (char *)default_url;
    if (url_obj) { resp_free(url_obj); url_obj = NULL; }
  }

  rtpproxy_client = (rtpp_client_t *)malloc(sizeof(rtpp_client_t));
  if (!rtpproxy_client) {
    if (url != default_url) free(url);
    return -1;
  }

  if (rtpp_client_init(rtpproxy_client, url) < 0) {
    free(rtpproxy_client);
    rtpproxy_client = NULL;
    if (url != default_url) free(url);
    return -1;
  }

  if (url != default_url) free(url);

  return 0;
}

rtpp_client_t *rtpproxy_get_client(void) {
  return rtpproxy_client;
}

const char *rtpproxy_get_fallback_ip(void) {
  if (!rtpproxy_client) return NULL;
  
  /* For TCP/UDP, return the configured host */
  if (rtpproxy_client->type == RTPP_TYPE_TCP || rtpproxy_client->type == RTPP_TYPE_UDP) {
    return rtpproxy_client->host;
  }
  
  /* For Unix sockets, caller should use PBX's own IP */
  return NULL;
}
