#include "domain/pbx/group.h"

#include <stdlib.h>
#include <string.h>

#include "common/resp.h"
#include "domain/config.h"
#include "rxi/log.h"

#define MAX_GROUPS 64

typedef struct {
  char *prefix;
  int   allow_incoming_cross_group;
  int   allow_outgoing_cross_group;
} group_config_t;

static group_config_t groups[MAX_GROUPS];
static int            group_count = 0;

static void group_config_free_entry(group_config_t *g) {
  if (!g) return;
  free(g->prefix);
  g->prefix = NULL;
  g->allow_incoming_cross_group = 1;
  g->allow_outgoing_cross_group = 0;
}

void group_config_free(void) {
  for (int i = 0; i < group_count; i++) {
    group_config_free_entry(&groups[i]);
  }
  group_count = 0;
}

static int longest_prefix_match(const char *ext, const char *prefix) {
  if (!ext || !prefix) return 0;
  size_t ext_len = strlen(ext);
  size_t pre_len  = strlen(prefix);
  if (pre_len > ext_len) return 0;
  return strncmp(ext, prefix, pre_len) == 0 ? (int)pre_len : 0;
}

const char *group_find_for_extension(const char *extension) {
  if (!extension) return NULL;

  int  best_match_len = 0;
  char *best_prefix  = NULL;

  for (int i = 0; i < group_count; i++) {
    int match_len = longest_prefix_match(extension, groups[i].prefix);
    if (match_len > best_match_len) {
      best_match_len = match_len;
      best_prefix    = groups[i].prefix;
    }
  }

  return best_prefix;
}

bool group_get_allow_incoming_cross_group(const char *group_prefix) {
  if (!group_prefix) return true;

  for (int i = 0; i < group_count; i++) {
    if (groups[i].prefix && strcmp(groups[i].prefix, group_prefix) == 0) {
      return groups[i].allow_incoming_cross_group != 0;
    }
  }
  return true;
}

bool group_get_allow_outgoing_cross_group(const char *group_prefix) {
  if (!group_prefix) return false;

  for (int i = 0; i < group_count; i++) {
    if (groups[i].prefix && strcmp(groups[i].prefix, group_prefix) == 0) {
      return groups[i].allow_outgoing_cross_group != 0;
    }
  }
  return false;
}

void group_config_init(void) {
  group_config_free();

  if (!domain_cfg) {
    log_warn("group: domain_cfg not initialized");
    return;
  }

  for (size_t i = 0; i < domain_cfg->u.arr.n && group_count < MAX_GROUPS; i++) {
    resp_object *elem = &domain_cfg->u.arr.elem[i];
    if (elem->type != RESPT_BULK || !elem->u.s) continue;

    if (strncmp(elem->u.s, "group:", 6) == 0) {
      const char *prefix = elem->u.s + 6;
      if (!prefix[0]) {
        log_warn("group: empty group prefix, skipping");
        continue;
      }

      resp_object *grp_cfg = resp_map_get(domain_cfg, elem->u.s);
      if (!grp_cfg || grp_cfg->type != RESPT_ARRAY) {
        log_warn("group: %s section not found in config", elem->u.s);
        continue;
      }

      groups[group_count].prefix = strdup(prefix);

      const char *inc = resp_map_get_string(grp_cfg, "allow_incoming_cross_group");
      groups[group_count].allow_incoming_cross_group = (inc && strcmp(inc, "true") == 0) || (inc && strcmp(inc, "1") == 0) ? 1 : 0;
      if (!inc) {
        groups[group_count].allow_incoming_cross_group = 1;
      }

      const char *out = resp_map_get_string(grp_cfg, "allow_outgoing_cross_group");
      groups[group_count].allow_outgoing_cross_group = (out && strcmp(out, "true") == 0) || (out && strcmp(out, "1") == 0) ? 1 : 0;

      log_info("group: loaded %s (incoming=%d, outgoing=%d)", prefix,
               groups[group_count].allow_incoming_cross_group,
               groups[group_count].allow_outgoing_cross_group);

      group_count++;
    }
  }

  if (group_count == 0) {
    log_warn("group: no groups configured");
  }
}
