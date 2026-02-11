/*
 * Upbx plugin API: thin wrapper around PluginModule; application-specific
 * config (upbx_config) and event semantics (REGISTER/INVITE query responses).
 * Started from AppModule after config load.
 */
#include <stdlib.h>
#include <string.h>

#include "rxi/log.h"
#include "config.h"
#include "AppModule/plugin.h"
#include "PluginModule/plugin.h"

#define PLUGIN_SECTION_PREFIX "plugin:"
#define PLUGIN_SECTION_PREFIX_LEN (sizeof(PLUGIN_SECTION_PREFIX) - 1)

static unsigned long long section_hash(resp_object *map) {
  if (!map || map->type != RESPT_ARRAY) return 0;
  unsigned long long h = 0;
  for (size_t i = 0; i < map->u.arr.n; i++) {
    resp_object *e = &map->u.arr.elem[i];
    if (e->type == RESPT_BULK || e->type == RESPT_SIMPLE) {
      const char *s = e->u.s;
      if (s) for (; *s; s++) h = h * 33ULL + (unsigned char)*s;
    }
  }
  return h;
}

/* Parse restart_on_update from section map: 0 or 1 only; default 0. */
static int section_restart_on_update(resp_object *sec) {
  resp_object *v = resp_map_get(sec, "restart_on_update");
  if (!v || v->type != RESPT_INT) return 0;
  return (v->u.i == 1) ? 1 : 0;
}

static void after_discovery_send_config(const char *plugin_name, void *user) {
  (void)user;
  char section_buf[64];
  size_t plen = strlen(plugin_name);
  if (plen + PLUGIN_SECTION_PREFIX_LEN >= sizeof(section_buf)) return;
  memcpy(section_buf, PLUGIN_SECTION_PREFIX, PLUGIN_SECTION_PREFIX_LEN);
  memcpy(section_buf + PLUGIN_SECTION_PREFIX_LEN, plugin_name, plen + 1);
  resp_object *map = config_section_get(section_buf);
  if (!map) return;
  if (plugmod_has_method(plugin_name, "config.set")) {
    plugmod_invoke(plugin_name, "config.set", 1, (const resp_object *const *)&map);
  } else if (plugmod_has_method(plugin_name, "set")) {
    resp_object *config_key = (resp_object *)malloc(sizeof(resp_object));
    if (config_key) {
      config_key->type = RESPT_BULK;
      config_key->u.s = strdup("config");
      if (config_key->u.s) {
        const resp_object *argv[] = { config_key, map };
        plugmod_invoke(plugin_name, "set", 2, argv);
        free(config_key->u.s);
      }
      free(config_key);
    }
  }
  resp_free(map);
}

void plugin_sync(void) {
  resp_object *sections = config_sections_list();
  if (!sections || sections->type != RESPT_ARRAY) {
    if (sections) resp_free(sections);
    plugmod_sync(NULL, 0, "command", NULL, NULL);
    return;
  }
  plugmod_config_item *configs = NULL;
  char **names = NULL;
  char **execs = NULL;
  size_t n = 0;
  for (size_t i = 0; i < sections->u.arr.n; i++) {
    resp_object *e = &sections->u.arr.elem[i];
    const char *sec_name = (e->type == RESPT_BULK || e->type == RESPT_SIMPLE) ? e->u.s : NULL;
    if (!sec_name || strncmp(sec_name, PLUGIN_SECTION_PREFIX, PLUGIN_SECTION_PREFIX_LEN) != 0) continue;
    resp_object *sec = config_section_get(sec_name);
    if (!sec) continue;
    const char *exec_str = resp_map_get_string(sec, "exec");
    if (!exec_str || !exec_str[0]) { resp_free(sec); continue; }
    char *name_copy = strdup(sec_name + PLUGIN_SECTION_PREFIX_LEN);
    char *exec_copy = strdup(exec_str);
    if (!name_copy || !exec_copy) { free(name_copy); free(exec_copy); resp_free(sec); break; }
    plugmod_config_item *p = realloc(configs, (n + 1) * sizeof(plugmod_config_item));
    char **n_re = realloc(names, (n + 1) * sizeof(char *));
    char **e_re = realloc(execs, (n + 1) * sizeof(char *));
    if (!p || !n_re || !e_re) { free(name_copy); free(exec_copy); resp_free(sec); break; }
    configs = p;
    names = n_re;
    execs = e_re;
    names[n] = name_copy;
    execs[n] = exec_copy;
    configs[n].name = name_copy;
    configs[n].exec = exec_copy;
    configs[n].config_hash = section_hash(sec);
    configs[n].restart_on_update = section_restart_on_update(sec);
    n++;
    resp_free(sec);
  }
  resp_free(sections);
  plugmod_sync(configs, n, "command", after_discovery_send_config, NULL);
  for (size_t j = 0; j < n; j++) {
    free(names[j]);
    free(execs[j]);
  }
  free(names);
  free(execs);
  free(configs);
}

/* Start all plugins from config; uses COMMAND for discovery and extension./trunk./call. events. */
void plugin_start(upbx_config *cfg) {
  log_trace("plugin_start: entry");
  if (!cfg) return;
  plugmod_config_item *configs = NULL;
  size_t n = 0;
  for (size_t i = 0; i < cfg->plugin_count; i++) {
    if (!cfg->plugins[i].exec || !cfg->plugins[i].exec[0]) continue;
    plugmod_config_item *p = realloc(configs, (n + 1) * sizeof(plugmod_config_item));
    if (!p) break;
    configs = p;
    configs[n].name = cfg->plugins[i].name;
    configs[n].exec = cfg->plugins[i].exec;
    configs[n].config_hash = 0;
    configs[n].restart_on_update = 0;
    n++;
  }
  plugmod_start(configs, n, "command", after_discovery_send_config, NULL);
  log_info("plugins started (%zu loaded)", plugmod_count());
  free(configs);
}

void plugin_stop(void) {
  plugmod_stop();
}

int plugin_invoke(const char *plugin_name, const char *method, int argc, const resp_object *const *argv) {
  return plugmod_invoke(plugin_name, method, argc, argv);
}

int plugin_has_method(const char *plugin_name, const char *method_name) {
  return plugmod_has_method(plugin_name, method_name);
}

void plugin_notify_event(const char *event_name, int argc, const resp_object *const *argv) {
  plugmod_notify_event(event_name, argc, argv);
}

/* Build request map for extension.register: extension, trunk, from_user. Caller resp_frees. */
static resp_object *build_register_request_map(const char *extension_num, const char *trunk_name, const char *from_user) {
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "extension") != 0 || resp_array_append_bulk(map, extension_num ? extension_num : "") != 0 ||
      resp_array_append_bulk(map, "trunk") != 0 || resp_array_append_bulk(map, trunk_name ? trunk_name : "") != 0 ||
      resp_array_append_bulk(map, "from_user") != 0 || resp_array_append_bulk(map, from_user ? from_user : "") != 0) {
    resp_free(map);
    return NULL;
  }
  return map;
}

void plugin_query_register(const char *extension_num, const char *trunk_name, const char *from_user,
  int *out_allow) {
  *out_allow = -1; /* continue */
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_method(name, "extension.register")) continue;
    resp_object *request_map = build_register_request_map(extension_num, trunk_name, from_user);
    if (!request_map) continue;
    resp_object *r = NULL;
    if (plugmod_invoke_response(name, "extension.register", 1, (const resp_object *const *)&request_map, &r) != 0 || !r) {
      resp_free(request_map);
      continue;
    }
    resp_free(request_map);
    if (r->type != RESPT_ARRAY || (r->u.arr.n & 1)) {
      resp_free(r);
      continue;
    }
    const char *action_str = resp_map_get_string(r, "action");
    if (action_str && strcasecmp(action_str, "reject") == 0) {
      *out_allow = 0;
      resp_free(r);
      return;
    }
    if (action_str && strcasecmp(action_str, "accept") == 0) {
      *out_allow = 1;
      resp_free(r);
      return;
    }
    resp_free(r);
  }
}

/* Build request map: source_ext, destination, call_id, trunks (array of trunk maps: name, cid, did). Caller resp_frees. */
static resp_object *build_dialout_request_map(const char *source_ext, const char *destination, const char *call_id,
  config_trunk **trunks, size_t n_trunks) {
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "source_ext") != 0 || resp_array_append_bulk(map, source_ext ? source_ext : "") != 0 ||
      resp_array_append_bulk(map, "destination") != 0 || resp_array_append_bulk(map, destination ? destination : "") != 0 ||
      resp_array_append_bulk(map, "call_id") != 0 || resp_array_append_bulk(map, call_id ? call_id : "") != 0 ||
      resp_array_append_bulk(map, "trunks") != 0) {
    resp_free(map);
    return NULL;
  }
  resp_object *trunks_arr = resp_array_init();
  if (!trunks_arr) { resp_free(map); return NULL; }
  for (size_t t = 0; t < n_trunks; t++) {
    config_trunk *tr = trunks[t];
    resp_object *tm = resp_array_init();
    if (!tm) { resp_free(trunks_arr); resp_free(map); return NULL; }
    if (resp_array_append_bulk(tm, "name") != 0 || resp_array_append_bulk(tm, tr->name ? tr->name : "") != 0 ||
        resp_array_append_bulk(tm, "cid") != 0 || resp_array_append_bulk(tm, tr->cid ? tr->cid : "") != 0 ||
        resp_array_append_bulk(tm, "did") != 0) {
      resp_free(tm);
      resp_free(trunks_arr);
      resp_free(map);
      return NULL;
    }
    resp_object *did_arr = resp_array_init();
    if (!did_arr) { resp_free(tm); resp_free(trunks_arr); resp_free(map); return NULL; }
    for (size_t d = 0; d < tr->did_count; d++) {
      if (resp_array_append_bulk(did_arr, tr->dids[d] ? tr->dids[d] : "") != 0) {
        resp_free(did_arr);
        resp_free(tm);
        resp_free(trunks_arr);
        resp_free(map);
        return NULL;
      }
    }
    if (resp_array_append_obj(tm, did_arr) != 0) { resp_free(did_arr); resp_free(tm); resp_free(trunks_arr); resp_free(map); return NULL; }
    if (resp_array_append_obj(trunks_arr, tm) != 0) { resp_free(tm); resp_free(trunks_arr); resp_free(map); return NULL; }
  }
  if (resp_array_append_obj(map, trunks_arr) != 0) { resp_free(trunks_arr); resp_free(map); return NULL; }
  return map;
}

/* Build request map for call.dialin: trunk, did, destinations (array), call_id. Caller resp_frees. */
static resp_object *build_dialin_request_map(const char *trunk_name, const char *did, const char **target_extensions, size_t n_targets, const char *call_id) {
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "trunk") != 0 || resp_array_append_bulk(map, trunk_name ? trunk_name : "") != 0 ||
      resp_array_append_bulk(map, "did") != 0 || resp_array_append_bulk(map, did ? did : "") != 0 ||
      resp_array_append_bulk(map, "destinations") != 0) {
    resp_free(map);
    return NULL;
  }
  resp_object *dests = resp_array_init();
  if (!dests) { resp_free(map); return NULL; }
  for (size_t k = 0; k < n_targets; k++) {
    if (resp_array_append_bulk(dests, target_extensions[k] ? target_extensions[k] : "") != 0) {
      resp_free(dests);
      resp_free(map);
      return NULL;
    }
  }
  if (resp_array_append_obj(map, dests) != 0) { resp_free(dests); resp_free(map); return NULL; }
  if (resp_array_append_bulk(map, "call_id") != 0 || resp_array_append_bulk(map, call_id ? call_id : "") != 0) {
    resp_free(map);
    return NULL;
  }
  return map;
}

/* Apply trunk override: from current_trunks (n_current), build new list ordered/filtered by names (string or array).
 * Returns new array and count; caller frees the array (not the config_trunk*). */
static config_trunk **apply_trunk_override(config_trunk **current_trunks, size_t n_current,
  resp_object *trunk_val, size_t *out_n) {
  *out_n = 0;
  if (!trunk_val || !current_trunks) return NULL;
  size_t names_cap = 64;
  const char **names = malloc(names_cap * sizeof(const char *));
  if (!names) return NULL;
  size_t n_names = 0;
  if (trunk_val->type == RESPT_BULK || trunk_val->type == RESPT_SIMPLE) {
    if (trunk_val->u.s && trunk_val->u.s[0]) {
      names[n_names++] = trunk_val->u.s;
    }
  } else if (trunk_val->type == RESPT_ARRAY) {
    for (size_t i = 0; i < trunk_val->u.arr.n && n_names < names_cap; i++) {
      resp_object *e = &trunk_val->u.arr.elem[i];
      const char *s = (e->type == RESPT_BULK || e->type == RESPT_SIMPLE) ? e->u.s : NULL;
      if (s && s[0]) names[n_names++] = s;
    }
  }
  if (n_names == 0) { free(names); return NULL; }
  config_trunk **out = malloc(n_names * sizeof(config_trunk *));
  if (!out) { free(names); return NULL; }
  size_t out_n_val = 0;
  for (size_t i = 0; i < n_names; i++) {
    for (size_t j = 0; j < n_current; j++) {
      if (current_trunks[j]->name && strcmp(current_trunks[j]->name, names[i]) == 0) {
        out[out_n_val++] = current_trunks[j];
        break;
      }
    }
  }
  free(names);
  *out_n = out_n_val;
  return out;
}

void plugin_query_dialout(upbx_config *cfg, const char *source_ext, const char *destination, const char *call_id,
  config_trunk **initial_trunks, size_t n_initial_trunks,
  int *out_action, int *out_reject_code, char **out_target_override,
  char ***out_trunk_override, int *out_trunk_override_n) {
  (void)cfg;
  *out_action = 0;
  *out_reject_code = 403;
  *out_target_override = NULL;
  *out_trunk_override = NULL;
  *out_trunk_override_n = -1;
  char *current_destination = strdup(destination ? destination : "");
  if (!current_destination) return;
  config_trunk **current_trunks = NULL;
  size_t n_current = n_initial_trunks;
  int trunk_override_was_set = 0;
  if (n_initial_trunks > 0 && initial_trunks) {
    current_trunks = malloc(n_initial_trunks * sizeof(config_trunk *));
    if (!current_trunks) { free(current_destination); return; }
    memcpy(current_trunks, initial_trunks, n_initial_trunks * sizeof(config_trunk *));
  }
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_method(name, "call.dialout")) continue;
    resp_object *request_map = build_dialout_request_map(source_ext, current_destination, call_id, current_trunks, n_current);
    if (!request_map) continue;
    resp_object *r = NULL;
    if (plugmod_invoke_response(name, "call.dialout", 1, (const resp_object *const *)&request_map, &r) != 0 || !r) {
      resp_free(request_map);
      continue;
    }
    resp_free(request_map);
    if (r->type != RESPT_ARRAY || (r->u.arr.n & 1)) {
      log_error("plugin %s: call.dialout returned invalid response (not a map)", name);
      resp_free(r);
      continue;
    }
    const char *action_str = resp_map_get_string(r, "action");
    if (!action_str) {
      log_error("plugin %s: call.dialout response missing action", name);
      resp_free(r);
      continue;
    }
    if (strcasecmp(action_str, "reject") == 0) {
      *out_action = 1;
      resp_object *code_val = resp_map_get(r, "reject_code");
      if (code_val && code_val->type == RESPT_INT) {
        *out_reject_code = (int)code_val->u.i;
        if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      }
      resp_free(r);
      free(current_destination);
      free(current_trunks);
      return;
    }
    if (strcasecmp(action_str, "accept") == 0) {
      *out_action = 2;
      const char *d = resp_map_get_string(r, "destination");
      if (d && d[0]) {
        free(current_destination);
        current_destination = strdup(d);
      }
      resp_object *trunk_val = resp_map_get(r, "trunk");
      if (trunk_val) {
        trunk_override_was_set = 1;
        config_trunk **new_trunks = apply_trunk_override(current_trunks, n_current, trunk_val, &n_current);
        free(current_trunks);
        current_trunks = new_trunks;
      }
      resp_free(r);
      continue;
    }
    resp_free(r);
  }
  if (*out_action == 2) {
    *out_target_override = current_destination;
    current_destination = NULL;
    if (trunk_override_was_set) {
      *out_trunk_override_n = (int)n_current;
      if (n_current > 0 && current_trunks) {
        char **names = malloc(n_current * sizeof(char *));
        if (names) {
          for (size_t k = 0; k < n_current; k++)
            names[k] = current_trunks[k]->name ? strdup(current_trunks[k]->name) : NULL;
          *out_trunk_override = names;
        }
      }
    }
  }
  free(current_destination);
  free(current_trunks);
}

void plugin_query_dialin(const char *trunk_name, const char *did, const char **target_extensions, size_t n_targets, const char *call_id,
  int *out_action, int *out_reject_code, char ***out_targets, size_t *out_n) {
  *out_action = 0;
  *out_reject_code = 403;
  *out_targets = NULL;
  *out_n = 0;
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_method(name, "call.dialin")) continue;
    resp_object *request_map = build_dialin_request_map(trunk_name, did, target_extensions, n_targets, call_id);
    if (!request_map) continue;
    resp_object *r = NULL;
    if (plugmod_invoke_response(name, "call.dialin", 1, (const resp_object *const *)&request_map, &r) != 0 || !r) {
      resp_free(request_map);
      continue;
    }
    resp_free(request_map);
    if (r->type != RESPT_ARRAY || (r->u.arr.n & 1)) {
      resp_free(r);
      continue;
    }
    const char *action_str = resp_map_get_string(r, "action");
    if (action_str && strcasecmp(action_str, "reject") == 0) {
      *out_action = 1;
      resp_object *code_val = resp_map_get(r, "reject_code");
      if (code_val && code_val->type == RESPT_INT) {
        *out_reject_code = (int)code_val->u.i;
        if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      }
      resp_free(r);
      return;
    }
    if (action_str && strcasecmp(action_str, "accept") == 0) {
      resp_object *dests_val = resp_map_get(r, "destinations");
      if (dests_val && dests_val->type == RESPT_ARRAY) {
        size_t n = dests_val->u.arr.n;
        if (n == 0) {
          log_error("plugin %s: call.dialin accept with empty destinations array, treating as continue", name);
        } else {
          char **targets = (char **)malloc(n * sizeof(char *));
          if (targets) {
            for (size_t j = 0; j < n; j++) {
              resp_object *elem = &dests_val->u.arr.elem[j];
              targets[j] = (elem->type == RESPT_BULK || elem->type == RESPT_SIMPLE) && elem->u.s
                ? strdup(elem->u.s) : NULL;
            }
            *out_targets = targets;
            *out_n = n;
            *out_action = 2;
          }
          resp_free(r);
          return;
        }
      }
    }
    resp_free(r);
  }
}

size_t plugin_count(void) {
  return plugmod_count();
}

const char *plugin_name_at(size_t i) {
  return plugmod_name_at(i);
}
