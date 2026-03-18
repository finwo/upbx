#ifndef UPBX_CONFIG_H
#define UPBX_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "finwo/url-parser.h"

struct upbx_config;

struct upbx_group {
  char *id;
  bool allow_outgoing_cross_group;
  bool allow_incoming_cross_group;
  struct upbx_group *next;
};

struct upbx_extension {
  char *id;
  char *name;
  char *secret;
  char *group;
  struct sockaddr_storage remote_addr;
  char *pbx_addr;
  char *contact;
  int64_t expires;
  struct upbx_extension *next;
};

struct upbx_trunk_rewrite {
  char *pattern;
  char *replace;
  struct upbx_trunk_rewrite *next;
};

struct upbx_trunk {
  char *name;
  struct parsed_url *address;
  char **dids;
  size_t n_dids;
  char *cid;
  char **groups;
  size_t n_groups;
  struct upbx_trunk_rewrite *rewrites;
  char *registered_contact;
  struct upbx_trunk *next;
};

struct upbx_rtpproxy {
  struct parsed_url *url;
  struct upbx_rtpproxy *next;
};

struct upbx_config {
  char *address;
  bool daemonize;
  char *data_dir;
  struct upbx_rtpproxy *rtpproxies;
  struct upbx_rtpproxy *rtpproxy_current;
  char **emergency_numbers;
  size_t n_emergency_numbers;

  struct upbx_group *groups;
  struct upbx_extension *extensions;
  struct upbx_trunk *trunks;
};

struct upbx_config *upbx_config_load(const char *filename);
void upbx_config_free(struct upbx_config *cfg);

const char *upbx_config_get_emergency_number(const struct upbx_config *cfg, size_t idx);
size_t upbx_config_get_emergency_count(const struct upbx_config *cfg);

struct upbx_group *upbx_config_find_group_by_prefix(const struct upbx_config *cfg, const char *ext_id);

struct upbx_extension *upbx_config_find_extension(const struct upbx_config *cfg, const char *ext_id);
struct upbx_extension *upbx_config_find_extension_by_addr(const struct upbx_config *cfg, const struct sockaddr_storage *addr);

struct upbx_trunk *upbx_config_find_trunk(const struct upbx_config *cfg, const char *trunk_name);
struct upbx_trunk **upbx_config_find_trunks_by_group(const struct upbx_config *cfg, const char *group, size_t *count);

char *upbx_config_trunk_rewrite(const struct upbx_trunk *trunk, const char *number);

#endif // UPBX_CONFIG_H
