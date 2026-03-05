#ifndef __APPMODULE_PBX_CALL_H__
#define __APPMODULE_PBX_CALL_H__

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

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
  time_t                  created;
  time_t                  answered;
  int                     ringing;
} call_t;

int call_route_invite(const char *from_ext, const char *to_ext, const char *call_id, const char *from_tag,
                      const char *sdp, size_t sdp_len, const char *source_ip, int source_port, char **out_sdp,
                      size_t *out_sdp_len, char **out_dest_sdp, size_t *out_dest_sdp_len);

void call_handle_bye(const char *call_id);
void call_handle_cancel(const char *call_id);

const call_t *call_find(const char *call_id);

void call_init(void);

#endif
