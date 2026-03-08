#ifndef UPBX_PBX_CALL_H
#define UPBX_PBX_CALL_H

#include <stdint.h>

typedef struct {
  char *call_id;
  char *source_extension;
  char *destination_extension;
  char *from_tag;
  char *to_tag;
  char *rtp_session_id;
  int source_media_port;
  int dest_media_port;
  char *source_advertise;
  char *dest_advertise;
} pbx_call_t;

void pbx_call_init(void);
void pbx_call_shutdown(void);

pbx_call_t *pbx_call_create(const char *call_id, const char *source_ext, const char *dest_ext, const char *from_tag);
pbx_call_t *pbx_call_find(const char *call_id);
void pbx_call_delete(const char *call_id);
void pbx_call_set_rtp_info(const char *call_id, const char *session_id, int src_port, int dst_port, const char *src_adv, const char *dst_adv);

#endif
