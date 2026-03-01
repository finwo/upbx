#ifndef UPBX_UDPHOLE_CLIENT_H
#define UPBX_UDPHOLE_CLIENT_H

#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  int fd;
  char *address;
  int connected;
} udphole_client_t;

typedef struct {
  int port;
  char *advertise_ip;
} udphole_socket_info_t;

int udphole_client_init(udphole_client_t *client, const char *address);
void udphole_client_cleanup(udphole_client_t *client);

int udphole_client_connect(udphole_client_t *client);
void udphole_client_disconnect(udphole_client_t *client);

int udphole_session_create(udphole_client_t *client, const char *session_id, int idle_expiry);
int udphole_session_destroy(udphole_client_t *client, const char *session_id);

int udphole_socket_create_listen(udphole_client_t *client, const char *session_id, const char *socket_id, udphole_socket_info_t *info);
int udphole_socket_create_connect(udphole_client_t *client, const char *session_id, const char *socket_id, const char *ip, int port, udphole_socket_info_t *info);
int udphole_socket_destroy(udphole_client_t *client, const char *session_id, const char *socket_id);

int udphole_forward_create(udphole_client_t *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id);
int udphole_forward_destroy(udphole_client_t *client, const char *session_id, const char *src_socket_id, const char *dst_socket_id);

int udphole_ping(udphole_client_t *client);

int udphole_global_init(void);
udphole_client_t *udphole_get_client(void);

const char *udphole_get_advertise_addr(void);

#endif
