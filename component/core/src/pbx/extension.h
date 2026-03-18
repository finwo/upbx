#ifndef PBX_EXTENSION_H
#define PBX_EXTENSION_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "config/config.h"

struct pbx_extension_entry;

typedef void (*extension_register_cb)(struct pbx_extension_entry *ext, bool success, void *udata);

struct pbx_extension_entry {
  struct upbx_config *config;

  struct upbx_extension *config_ext;

  struct sockaddr_storage remote_addr;
  char *pbx_addr;

  char *contact;
  int64_t expires;

  char *nonce;
  int64_t nonce_time;

  char id[64];
  struct pbx_extension_entry *next;
};

struct pbx_extension_registry {
  struct upbx_config *config;
  struct pbx_extension_entry *entries;
};

struct pbx_extension_registry *pbx_extension_create(struct upbx_config *config);
void pbx_extension_destroy(struct pbx_extension_registry *ext);

int pbx_extension_handle_register(struct pbx_extension_registry *pbx, struct upbx_extension *config_ext, const char *contact, int expires, const char *auth_header, const struct sockaddr_storage *src, const char *request_uri);

void pbx_extension_set_contact(struct pbx_extension_entry *ext, const char *contact, int64_t expires);
void pbx_extension_set_pbx_addr(struct pbx_extension_entry *ext, const char *pbx_addr);
struct pbx_extension_entry *pbx_extension_find_by_addr(const struct pbx_extension_registry *pbx, const struct sockaddr_storage *addr);

void pbx_extension_cleanup_expired(struct pbx_extension_registry *pbx);

char *pbx_extension_get_nonce(struct pbx_extension_registry *pbx, const struct sockaddr_storage *src);

#endif // PBX_EXTENSION_H
