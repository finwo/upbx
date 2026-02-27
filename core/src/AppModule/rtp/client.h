#ifndef __APPMODULE_RTP_CLIENT_H__
#define __APPMODULE_RTP_CLIENT_H__

#include <stddef.h>

typedef struct {
  int port;
  char *advertise_ip;
} rtp_session_info_t;

int rtp_client_create_session(const char *call_id, const char *remote_ip, int remote_port, const char *from_tag, rtp_session_info_t *info);
int rtp_client_lookup_session(const char *call_id, const char *remote_ip, int remote_port, const char *from_tag, rtp_session_info_t *info);
int rtp_client_delete_session(const char *call_id, const char *from_tag, const char *to_tag);
void rtp_client_free_info(rtp_session_info_t *info);

#endif