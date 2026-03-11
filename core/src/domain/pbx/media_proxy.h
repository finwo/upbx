#ifndef UPBX_PBX_MEDIA_PROXY_H
#define UPBX_PBX_MEDIA_PROXY_H

#include <stdbool.h>

void pbx_media_proxy_init(void);
void pbx_media_proxy_shutdown(void);

bool pbx_media_proxy_connect(void);
void pbx_media_proxy_disconnect(void);

int pbx_media_proxy_session_create(const char *session_id);
int pbx_media_proxy_session_destroy(const char *session_id);

typedef struct {
  int  port;
  char advertise_addr[64];
} pbx_media_proxy_socket_info_t;

int pbx_media_proxy_create_listen_socket(const char *session_id, const char *socket_id,
                                         pbx_media_proxy_socket_info_t *info);
int pbx_media_proxy_create_connect_socket(const char *session_id, const char *socket_id, const char *ip, int port);
int pbx_media_proxy_create_forward(const char *session_id, const char *src_socket_id, const char *dst_socket_id);

#endif
