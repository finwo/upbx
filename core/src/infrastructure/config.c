#include <stdlib.h>
#include <string.h>
#include "benhoyt/inih.h"
#include "rxi/log.h"
#include "infrastructure/config.h"
#include "common/resp.h"

resp_object *global_cfg = NULL;
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
  resp_array_append_bulk(sec, name);
  resp_array_append_bulk(sec, value);
  return 1;
}

void config_init(void) {
  global_cfg = resp_array_init();
  config_load(global_cfg, config_get_path());
}

int config_load(resp_object *cfg, const char *path) {
  return ini_parse(path, config_handler, cfg);
}

void config_pending_init(void) {
  pending_cfg = resp_array_init();
}

void config_swap(void) {
  resp_object *old = global_cfg;
  global_cfg = pending_cfg;
  pending_cfg = old;
  if (old) resp_free(old);
}

int config_reload(void) {
  config_pending_init();
  int r = config_load(pending_cfg, config_get_path());
  if (r < 0) return -1;
  config_swap();
  return 0;
}

void config_set_path(const char *path) {
  if (stored_config_path) free((void*)stored_config_path);
  stored_config_path = path ? strdup(path) : NULL;
}

const char *config_get_path(void) {
  return stored_config_path;
}