#include "domain/pbx/extension.h"

#include <stdlib.h>
#include <string.h>

#include "domain/config.h"
#include "rxi/log.h"

void pbx_extension_init(void) {
  if (!domain_cfg) {
    log_warn("pbx: domain_cfg is NULL in extension_init");
    return;
  }
  log_info("pbx: extension_init complete");
}

void pbx_extension_shutdown(void) {
}

static const char *find_longest_matching_group(const char *number) {
  if (!domain_cfg || !number) return NULL;

  for (size_t i = 0; i + 1 < domain_cfg->u.arr.n; i += 2) {
    const char *key = domain_cfg->u.arr.elem[i].u.s;
    if (!key || strncmp(key, "group:", 6) != 0) continue;

    const char *prefix = key + 6;
    size_t      plen   = strlen(prefix);
    if (strlen(number) >= plen && strncmp(number, prefix, plen) == 0) {
      log_debug("pbx: found group '%s' matching extension '%s'", prefix, number);
      return prefix;
    }
  }
  return NULL;
}

pbx_extension_t *pbx_extension_find(const char *number) {
  if (!domain_cfg || !number) return NULL;

  char ext_key[64];
  snprintf(ext_key, sizeof(ext_key), "ext:%s", number);

  resp_object *ext_sec = resp_map_get(domain_cfg, ext_key);
  if (!ext_sec || ext_sec->type != RESPT_ARRAY) return NULL;

  const char *secret       = resp_map_get_string(ext_sec, "secret");
  const char *name         = resp_map_get_string(ext_sec, "name");
  const char *group_prefix = find_longest_matching_group(number);

  if (!group_prefix) return NULL;

  pbx_extension_t *ext = calloc(1, sizeof(pbx_extension_t));
  ext->number          = strdup(number);
  ext->secret          = secret ? strdup(secret) : NULL;
  ext->name            = name ? strdup(name) : NULL;
  ext->group_prefix    = strdup(group_prefix);

  return ext;
}

pbx_group_t *pbx_group_find(const char *prefix) {
  if (!domain_cfg || !prefix) return NULL;

  char group_key[64];
  snprintf(group_key, sizeof(group_key), "group:%s", prefix);

  resp_object *group_sec = resp_map_get(domain_cfg, group_key);
  if (!group_sec || group_sec->type != RESPT_ARRAY) return NULL;

  pbx_group_t *grp = calloc(1, sizeof(pbx_group_t));
  grp->prefix      = strdup(prefix);

  const char *val                 = resp_map_get_string(group_sec, "allow_incoming_cross_group");
  grp->allow_incoming_cross_group = (val && strcmp(val, "0") == 0) ? 0 : 1;

  val                             = resp_map_get_string(group_sec, "allow_outgoing_cross_group");
  grp->allow_outgoing_cross_group = (val && strcmp(val, "1") == 0) ? 1 : 0;

  return grp;
}
