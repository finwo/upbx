#ifndef __APPMODULE_PBX_CALL_H__
#define __APPMODULE_PBX_CALL_H__

#include <stdint.h>
#include <time.h>

struct call {
  struct call *next;
  char *call_id;
  char *source;
  char *destination;
  char *source_contact;
  char *dest_contact;
  char source_rtp_ip[64];
  int source_rtp_port;
  char dest_rtp_ip[64];
  int dest_rtp_port;
  time_t created;
  time_t answered;
  int active;
  int answered_flag;
  char direction[16];
  char *source_str;
  char *dest_str;
  char *trunk_name;
  size_t n_forks;
  size_t n_pending_exts;
};

typedef struct call call_t;

int call_route_invite(const char *from_ext, const char *to, const char *call_id, const char *sdp, char **out_sdp);
void call_handle_bye(const char *call_id);
void call_cleanup(void);

call_t *call_first(void);
call_t *call_find(const char *call_id);

#endif