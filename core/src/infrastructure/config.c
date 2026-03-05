#include "infrastructure/config.h"

#include <stdlib.h>
#include <string.h>

#include "benhoyt/inih.h"
#include "common/resp.h"
#include "domain/config.h"
#include "rxi/log.h"

resp_object *pending_cfg = NULL;

static const char *stored_config_path = NULL;

static int config_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  (void)lineno;
  resp_object *cfg = (resp_object *)user;
  resp_object *sec = resp_map_get(cfg, section);
  if (!sec || sec->type != RESPT_ARRAY) {
    sec = resp_array_init();
    resp_map_set(cfg, section, sec);
    sec = resp_map_get(cfg, section);
  }

  if (strcmp(name, "listen") == 0 ||
      strcmp(name, "address") == 0 ||
      strcmp(name, "rtpproxy") == 0) {
    resp_object *arr = resp_map_get(sec, name);
    if (!arr) {
      arr = resp_array_init();
      resp_map_set(sec, name, arr);
      arr = resp_map_get(sec, name);
    }
    if (!arr || arr->type != RESPT_ARRAY) {
      log_error("config: '%s' key already exists as non-array", name);
      return 0;
    }
    resp_array_append_bulk(arr, value);
  } else {
    resp_array_append_bulk(sec, name);
    resp_array_append_bulk(sec, value);
  }
  return 1;
}

void config_init(void) {
  if (pending_cfg) resp_free(pending_cfg);
  pending_cfg = resp_array_init();
  config_load(NULL, config_get_path());
  resp_object *old = domain_cfg;
  domain_cfg       = pending_cfg;
  pending_cfg      = NULL;
  if (old) resp_free(old);
}

int config_load(resp_object *cfg, const char *path) {
  resp_object *load_cfg = cfg;
  if (!load_cfg) {
    load_cfg = pending_cfg;
  }
  return ini_parse(path, config_handler, load_cfg);
}

void config_pending_init(void) {
  if (pending_cfg) resp_free(pending_cfg);
  pending_cfg = resp_array_init();
}

int config_reload(void) {
  config_pending_init();
  int r = config_load(NULL, config_get_path());
  if (r < 0) return -1;
  resp_object *old = domain_cfg;
  domain_cfg       = pending_cfg;
  pending_cfg      = NULL;
  if (old) resp_free(old);
  return 0;
}

void config_set_path(const char *path) {
  if (stored_config_path) free((void *)stored_config_path);
  stored_config_path = path ? strdup(path) : NULL;
}

const char *config_get_path(void) {
  return stored_config_path;
}
