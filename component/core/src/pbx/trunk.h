#ifndef PBX_TRUNK_H
#define PBX_TRUNK_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "config/config.h"

struct pbx_trunk;

struct pbx_trunk {
  struct upbx_config *config;

  struct pbx_trunk *next;

  struct upbx_trunk *config_trunk;
  int registered;
  char *registered_contact;
  int64_t registration_expires;
  int64_t last_register_attempt;

  int fd;
};

struct pbx_trunk *pbx_trunk_create(struct upbx_config *config);
void pbx_trunk_destroy(struct pbx_trunk *trunks);

int pbx_trunk_register(struct pbx_trunk *trunk, struct upbx_trunk *config_trunk);
int pbx_trunk_handle_response(struct pbx_trunk *trunk, const char *call_id, int status_code, const char *auth_header);

struct pbx_trunk *pbx_trunk_find_by_name(struct pbx_trunk *trunks, const char *name);
struct pbx_trunk *pbx_trunk_find_by_contact(struct pbx_trunk *trunks, const char *contact);

int pbx_trunk_get_fds(struct pbx_trunk *trunks, int **fds);
int pbx_trunk_send(struct pbx_trunk *trunk, const char *data, size_t len);

#endif // PBX_TRUNK_H
