#ifndef UPBX_PBX_REGISTRATION_H
#define UPBX_PBX_REGISTRATION_H

#include <stdint.h>
#include <sys/socket.h>

typedef struct {
  char extension[32];
  char group_prefix[32];
  char contact[256];
  int fd;
  struct sockaddr_storage remote_addr;
  int64_t expires;
  char pbx_addr[128];
} pbx_registration_t;

void pbx_registration_init(void);
void pbx_registration_shutdown(void);

pbx_registration_t *pbx_registration_find(const char *extension);
pbx_registration_t *pbx_registration_create(const char *extension, const char *contact, int fd, const struct sockaddr *remote_addr, int expires);
void pbx_registration_delete(const char *extension);
pbx_registration_t *pbx_registration_find_by_remote_addr(const struct sockaddr *remote_addr);
int pbx_registration_update_pbx_addr(const char *extension, const char *pbx_addr);

int pbx_registration_cleanup(void);
const char *pbx_registration_get_addrmap_dir(void);

#endif
