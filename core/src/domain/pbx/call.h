#ifndef __APPMODULE_PBX_CALL_H__
#define __APPMODULE_PBX_CALL_H__

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sip_message.h"

#define MAX_MEDIA_STREAMS 8

typedef struct {
  char                   *call_id;
  char                   *source_ext;
  char                   *dest_ext;
  char                   *source_contact;
  char                   *dest_contact;
  struct sockaddr_storage source_addr;
  struct sockaddr_storage dest_addr;
  char                    source_rtp_ip[MAX_MEDIA_STREAMS][64];
  int                     source_rtp_port[MAX_MEDIA_STREAMS];
  char                    dest_rtp_ip[MAX_MEDIA_STREAMS][64];
  int                     dest_rtp_port[MAX_MEDIA_STREAMS];
  char                   *source_socket_ids[MAX_MEDIA_STREAMS];
  char                   *dest_socket_ids[MAX_MEDIA_STREAMS];
  int                     num_media_streams;
  char                   *from_tag;
  char                   *to_tag;
  char                   *dest_branch;
  time_t                  created;
  time_t                  answered;
  time_t                  ringing;
  time_t                  cancelling;
} call_t;

char *call_handle_invite(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
);

char *call_handle_bye(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
);

char *call_handle_cancel(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
);

char *call_handle_response(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
);

const call_t *call_find(const char *call_id);

void call_init(void);

#endif
