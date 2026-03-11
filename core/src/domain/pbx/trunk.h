#ifndef UPBX_PBX_TRUNK_H
#define UPBX_PBX_TRUNK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "common/scheduler.h"

typedef struct {
  char *name;
  char *protocol;
  char *host;
  int   port;
  char *username;
  char *password;
  char *cid;
  char **dids;
  size_t did_count;
  char **groups;
  size_t group_count;
} trunk_config_t;

typedef struct {
  trunk_config_t         *cfg;

  /* socket */
  int                     fd;
  int                     fds[2];  /* sched_has_data format: [0]=count, [1]=fd */
  struct sockaddr_storage remote_addr;
  socklen_t               remote_addr_len;

  /* registration timing */
  time_t                  registered_at;
  time_t                  next_register;
  int                     expires_seconds;

  /* backoff */
  int                     retry_count;

  /* transaction state */
  char                    call_id[64];
  int                     cseq;

  /* auth challenge */
  char                   *nonce;
  char                   *realm;
  int                     auth_challenged;

  /* receive buffer */
  char                    recv_buf[4096];
} trunk_state_t;

void pbx_trunk_init(void);
void pbx_trunk_shutdown(void);
void pbx_trunk_reload(void);

int trunk_register_pt(int64_t timestamp, struct pt_task *task);

#endif
