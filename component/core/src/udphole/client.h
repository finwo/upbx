#ifndef UDPHOLE_CLIENT_H
#define UDPHOLE_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "config/config.h"
#include "common/scheduler.h"
#include "finwo/resp.h"

struct udphole_client;

typedef void (*udphole_connect_cb)(struct udphole_client *client, bool success, void *udata);
typedef void (*udphole_response_cb)(struct udphole_client *client, resp_object *response, void *udata);

struct udphole_socket_info {
  char *socket_id;
  int local_port;
  char *advertised_ip;
};

struct udphole_client {
  struct upbx_config *config;

  int fd;
  struct sockaddr_storage remote_addr;
  char *connected_url;
  struct upbx_rtpproxy *current_rtpproxy;

  char rbuf[4096];
  size_t rlen;
  char *wbuf;
  size_t wlen;
  size_t wcap;

  int retry_count;
  int max_retries;
};

struct udphole_client *udphole_client_create(struct upbx_config *config);
void udphole_client_destroy(struct udphole_client *client);

int udphole_client_connect(struct udphole_client *client, udphole_connect_cb cb, void *udata);
void udphole_client_disconnect(struct udphole_client *client);

int udphole_client_session_create(struct udphole_client *client, const char *session_id, int idle_expiry);
int udphole_client_session_destroy(struct udphole_client *client, const char *session_id);

int udphole_client_socket_create_listen(struct udphole_client *client, const char *session_id, const char *socket_id, struct udphole_socket_info *info);
int udphole_client_socket_create_connect(struct udphole_client *client, const char *session_id, const char *socket_id, const char *ip, int port, struct udphole_socket_info *info);
int udphole_client_socket_destroy(struct udphole_client *client, const char *session_id, const char *socket_id);

int udphole_client_forward_create(struct udphole_client *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id);
int udphole_client_forward_destroy(struct udphole_client *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id);

int udphole_client_get_fds(struct udphole_client *client, int **fds);

const char *udphole_client_get_advertised_ip(struct udphole_client *client);

#endif // UDPHOLE_CLIENT_H
