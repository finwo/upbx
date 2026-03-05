#ifndef UPBX_UDPHOLE_CLIENT_H
#define UPBX_UDPHOLE_CLIENT_H

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

#include "common/resp.h"

typedef struct udphole_transport udphole_transport_t;

typedef struct {
  int (*connect)(void *self);
  void (*disconnect)(void *self);
  int (*send)(void *self, const char *cmd, size_t cmd_len);
  resp_object *(*recv)(void *self);
} udphole_transport_vtable;

struct udphole_transport {
  const udphole_transport_vtable *vtable;
  void                           *impl;
};

typedef struct {
  udphole_transport_t transport;
  char               *advertise_ip;
} udphole_client_t;

typedef struct {
  int   port;
  char *advertise_ip;
} udphole_socket_info_t;

typedef struct rtpproxy_node {
  udphole_client_t       *client;
  struct rtpproxy_node *next;
} rtpproxy_node_t;

typedef struct {
  rtpproxy_node_t *head;
  rtpproxy_node_t *current;
  int              count;
} rtpproxy_pool_t;

void udphole_client_init_global(void);
void udphole_client_cleanup_global(void);

udphole_client_t *udphole_client_create(const char *address, const char *auth_user, const char *auth_pass);
void              udphole_client_destroy(udphole_client_t *client);

int  udphole_client_connect(udphole_client_t *client);
void udphole_client_disconnect(udphole_client_t *client);

int udphole_session_create(udphole_client_t *client, const char *session_id, int idle_expiry);
int udphole_session_destroy(udphole_client_t *client, const char *session_id);

int udphole_socket_create_listen(udphole_client_t *client, const char *session_id, const char *socket_id,
                                 udphole_socket_info_t *info);
int udphole_socket_create_connect(udphole_client_t *client, const char *session_id, const char *socket_id,
                                  const char *ip, int port, udphole_socket_info_t *info);
int udphole_socket_destroy(udphole_client_t *client, const char *session_id, const char *socket_id);

int udphole_forward_create(udphole_client_t *client, const char *session_id, const char *src_socket_id,
                           const char *dst_socket_id);
int udphole_forward_destroy(udphole_client_t *client, const char *session_id, const char *src_socket_id,
                            const char *dst_socket_id);

int udphole_ping(udphole_client_t *client);

udphole_client_t *udphole_get_client(void);
const char       *udphole_get_advertise_addr(void);

#endif
