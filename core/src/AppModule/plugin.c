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

static const char *event_prefixes[] = { "extension.", "trunk.", "call." };
#define N_EVENT_PREFIXES (sizeof(event_prefixes) / sizeof(event_prefixes[0]))
#define PLUGIN_SECTION_PREFIX "plugin:"
#define PLUGIN_SECTION_PREFIX_LEN (sizeof(PLUGIN_SECTION_PREFIX) - 1)

static unsigned long long section_hash(plugmod_resp_object *map) {
  if (!map || map->type != PLUGMOD_RESPT_ARRAY) return 0;
  unsigned long long h = 0;
  for (size_t i = 0; i < map->u.arr.n; i++) {
    plugmod_resp_object *e = &map->u.arr.elem[i];
    if (e->type == PLUGMOD_RESPT_BULK || e->type == PLUGMOD_RESPT_SIMPLE) {
      const char *s = e->u.s;
      if (s) for (; *s; s++) h = h * 33ULL + (unsigned char)*s;
    }
  }
  return h;
}

void plugin_sync(void) {
  plugmod_resp_object *sections = config_sections_list();
  if (!sections || sections->type != PLUGMOD_RESPT_ARRAY) {
    if (sections) plugmod_resp_free(sections);
    plugmod_sync(NULL, 0, "command", event_prefixes, N_EVENT_PREFIXES);
    return;
  }
  plugmod_config_item *configs = NULL;
  char **names = NULL;
  char **execs = NULL;
  size_t n = 0;
  for (size_t i = 0; i < sections->u.arr.n; i++) {
    plugmod_resp_object *e = &sections->u.arr.elem[i];
    const char *sec_name = (e->type == PLUGMOD_RESPT_BULK || e->type == PLUGMOD_RESPT_SIMPLE) ? e->u.s : NULL;
    if (!sec_name || strncmp(sec_name, PLUGIN_SECTION_PREFIX, PLUGIN_SECTION_PREFIX_LEN) != 0) continue;
    plugmod_resp_object *sec = config_section_get(sec_name);
    if (!sec) continue;
    const char *exec_str = plugmod_resp_map_get_string(sec, "exec");
    if (!exec_str || !exec_str[0]) { plugmod_resp_free(sec); continue; }
    char *name_copy = strdup(sec_name + PLUGIN_SECTION_PREFIX_LEN);
    char *exec_copy = strdup(exec_str);
    if (!name_copy || !exec_copy) { free(name_copy); free(exec_copy); plugmod_resp_free(sec); break; }
    plugmod_config_item *p = realloc(configs, (n + 1) * sizeof(plugmod_config_item));
    char **n_re = realloc(names, (n + 1) * sizeof(char *));
    char **e_re = realloc(execs, (n + 1) * sizeof(char *));
    if (!p || !n_re || !e_re) { free(name_copy); free(exec_copy); plugmod_resp_free(sec); break; }
    configs = p;
    names = n_re;
    execs = e_re;
    names[n] = name_copy;
    execs[n] = exec_copy;
    configs[n].name = name_copy;
    configs[n].exec = exec_copy;
    configs[n].config_hash = section_hash(sec);
    n++;
    plugmod_resp_free(sec);
  }
  plugmod_resp_free(sections);
  plugmod_sync(configs, n, "command", event_prefixes, N_EVENT_PREFIXES);
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
    n++;
  }
  plugmod_start(configs, n, "command", event_prefixes, N_EVENT_PREFIXES);
  log_info("plugins started (%zu loaded)", plugmod_count());
  free(configs);
}

void plugin_stop(void) {
  plugmod_stop();
}

int plugin_invoke(const char *plugin_name, const char *method, int argc, const plugmod_resp_object *const *argv) {
  return plugmod_invoke(plugin_name, method, argc, argv);
}

int plugin_has_event(const char *plugin_name, const char *event_name) {
  return plugmod_has_event(plugin_name, event_name);
}

void plugin_notify_event(const char *event_name, int argc, const plugmod_resp_object *const *argv) {
  plugmod_notify_event(event_name, argc, argv);
}

/* Build request map for extension.register: extension, trunk, from_user. Caller plugmod_resp_frees. */
static plugmod_resp_object *build_register_request_map(const char *extension_num, const char *trunk_name, const char *from_user) {
  plugmod_resp_object *map = calloc(1, sizeof(plugmod_resp_object));
  if (!map) return NULL;
  map->type = PLUGMOD_RESPT_ARRAY;
  map->u.arr.n = 6;
  map->u.arr.elem = calloc(6, sizeof(plugmod_resp_object));
  if (!map->u.arr.elem) { free(map); return NULL; }
  plugmod_resp_object *e = map->u.arr.elem;
  e[0].type = PLUGMOD_RESPT_BULK; e[0].u.s = strdup("extension");
  e[1].type = PLUGMOD_RESPT_BULK; e[1].u.s = strdup(extension_num ? extension_num : "");
  e[2].type = PLUGMOD_RESPT_BULK; e[2].u.s = strdup("trunk");
  e[3].type = PLUGMOD_RESPT_BULK; e[3].u.s = strdup(trunk_name ? trunk_name : "");
  e[4].type = PLUGMOD_RESPT_BULK; e[4].u.s = strdup("from_user");
  e[5].type = PLUGMOD_RESPT_BULK; e[5].u.s = strdup(from_user ? from_user : "");
  if (!e[0].u.s || !e[1].u.s || !e[2].u.s || !e[3].u.s || !e[4].u.s || !e[5].u.s) {
    plugmod_resp_free(map);
    return NULL;
  }
  return map;
}

void plugin_query_register(const char *extension_num, const char *trunk_name, const char *from_user,
  int *out_allow) {
  *out_allow = -1; /* continue */
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_event(name, "extension.register")) continue;
    plugmod_resp_object *request_map = build_register_request_map(extension_num, trunk_name, from_user);
    if (!request_map) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "extension.register", 1, (const plugmod_resp_object *const *)&request_map, &r) != 0 || !r) {
      plugmod_resp_free(request_map);
      continue;
    }
    plugmod_resp_free(request_map);
    if (r->type != PLUGMOD_RESPT_ARRAY || (r->u.arr.n & 1)) {
      plugmod_resp_free(r);
      continue;
    }
    const char *action_str = plugmod_resp_map_get_string(r, "action");
    if (action_str && strcasecmp(action_str, "reject") == 0) {
      *out_allow = 0;
      plugmod_resp_free(r);
      return;
    }
    if (action_str && strcasecmp(action_str, "accept") == 0) {
      *out_allow = 1;
      plugmod_resp_free(r);
      return;
    }
    plugmod_resp_free(r);
  }
}

/* Build request map: source_ext, destination, call_id, trunks (array of trunk maps: name, cid, did). Caller plugmod_resp_frees. */
static plugmod_resp_object *build_dialout_request_map(const char *source_ext, const char *destination, const char *call_id,
  config_trunk **trunks, size_t n_trunks) {
  size_t map_entries = 8; /* 4 keys + 4 values */
  plugmod_resp_object *map = calloc(1, sizeof(plugmod_resp_object));
  if (!map) return NULL;
  map->type = PLUGMOD_RESPT_ARRAY;
  map->u.arr.n = map_entries;
  map->u.arr.elem = calloc(map_entries, sizeof(plugmod_resp_object));
  if (!map->u.arr.elem) { free(map); return NULL; }
  plugmod_resp_object *e = map->u.arr.elem;
  e[0].type = PLUGMOD_RESPT_BULK; e[0].u.s = strdup("source_ext");
  e[1].type = PLUGMOD_RESPT_BULK; e[1].u.s = strdup(source_ext ? source_ext : "");
  e[2].type = PLUGMOD_RESPT_BULK; e[2].u.s = strdup("destination");
  e[3].type = PLUGMOD_RESPT_BULK; e[3].u.s = strdup(destination ? destination : "");
  e[4].type = PLUGMOD_RESPT_BULK; e[4].u.s = strdup("call_id");
  e[5].type = PLUGMOD_RESPT_BULK; e[5].u.s = strdup(call_id ? call_id : "");
  e[6].type = PLUGMOD_RESPT_BULK; e[6].u.s = strdup("trunks");
  if (!e[0].u.s || !e[1].u.s || !e[2].u.s || !e[3].u.s || !e[4].u.s || !e[5].u.s || !e[6].u.s) {
    plugmod_resp_free(map);
    return NULL;
  }
  /* trunks value: array of trunk maps */
  plugmod_resp_object *trunks_arr = calloc(1, sizeof(plugmod_resp_object));
  if (!trunks_arr) { plugmod_resp_free(map); return NULL; }
  trunks_arr->type = PLUGMOD_RESPT_ARRAY;
  trunks_arr->u.arr.n = n_trunks;
  trunks_arr->u.arr.elem = n_trunks ? calloc(n_trunks, sizeof(plugmod_resp_object)) : NULL;
  if (n_trunks && !trunks_arr->u.arr.elem) { free(trunks_arr); plugmod_resp_free(map); return NULL; }
  e[7].type = PLUGMOD_RESPT_ARRAY;
  e[7].u.arr = trunks_arr->u.arr;
  free(trunks_arr);
  for (size_t t = 0; t < n_trunks; t++) {
    config_trunk *tr = trunks[t];
    plugmod_resp_object *tm = &e[7].u.arr.elem[t];
    tm->type = PLUGMOD_RESPT_ARRAY;
    tm->u.arr.n = 6; /* name, cid, did keys + values */
    tm->u.arr.elem = calloc(6, sizeof(plugmod_resp_object));
    if (!tm->u.arr.elem) { plugmod_resp_free(map); return NULL; }
    tm->u.arr.elem[0].type = PLUGMOD_RESPT_BULK; tm->u.arr.elem[0].u.s = strdup("name");
    tm->u.arr.elem[1].type = PLUGMOD_RESPT_BULK; tm->u.arr.elem[1].u.s = strdup(tr->name ? tr->name : "");
    tm->u.arr.elem[2].type = PLUGMOD_RESPT_BULK; tm->u.arr.elem[2].u.s = strdup("cid");
    tm->u.arr.elem[3].type = PLUGMOD_RESPT_BULK; tm->u.arr.elem[3].u.s = strdup(tr->cid ? tr->cid : "");
    tm->u.arr.elem[4].type = PLUGMOD_RESPT_BULK; tm->u.arr.elem[4].u.s = strdup("did");
    plugmod_resp_object *did_arr = calloc(1, sizeof(plugmod_resp_object));
    if (!did_arr) { plugmod_resp_free(map); return NULL; }
    did_arr->type = PLUGMOD_RESPT_ARRAY;
    did_arr->u.arr.n = tr->did_count;
    did_arr->u.arr.elem = tr->did_count ? calloc(tr->did_count, sizeof(plugmod_resp_object)) : NULL;
    if (tr->did_count && !did_arr->u.arr.elem) { free(did_arr); plugmod_resp_free(map); return NULL; }
    for (size_t d = 0; d < tr->did_count; d++) {
      did_arr->u.arr.elem[d].type = PLUGMOD_RESPT_BULK;
      did_arr->u.arr.elem[d].u.s = strdup(tr->dids[d] ? tr->dids[d] : "");
    }
    tm->u.arr.elem[5].type = PLUGMOD_RESPT_ARRAY;
    tm->u.arr.elem[5].u.arr = did_arr->u.arr;
    free(did_arr);
  }
  return map;
}

/* Build request map for call.dialin: trunk, did, destinations (array), call_id. Caller plugmod_resp_frees. */
static plugmod_resp_object *build_dialin_request_map(const char *trunk_name, const char *did, const char **target_extensions, size_t n_targets, const char *call_id) {
  plugmod_resp_object *map = calloc(1, sizeof(plugmod_resp_object));
  if (!map) return NULL;
  map->type = PLUGMOD_RESPT_ARRAY;
  map->u.arr.n = 8;
  map->u.arr.elem = calloc(8, sizeof(plugmod_resp_object));
  if (!map->u.arr.elem) { free(map); return NULL; }
  plugmod_resp_object *e = map->u.arr.elem;
  e[0].type = PLUGMOD_RESPT_BULK; e[0].u.s = strdup("trunk");
  e[1].type = PLUGMOD_RESPT_BULK; e[1].u.s = strdup(trunk_name ? trunk_name : "");
  e[2].type = PLUGMOD_RESPT_BULK; e[2].u.s = strdup("did");
  e[3].type = PLUGMOD_RESPT_BULK; e[3].u.s = strdup(did ? did : "");
  e[4].type = PLUGMOD_RESPT_BULK; e[4].u.s = strdup("destinations");
  plugmod_resp_object *dests = calloc(1, sizeof(plugmod_resp_object));
  if (!dests) { plugmod_resp_free(map); return NULL; }
  dests->type = PLUGMOD_RESPT_ARRAY;
  dests->u.arr.n = n_targets;
  dests->u.arr.elem = n_targets ? calloc(n_targets, sizeof(plugmod_resp_object)) : NULL;
  if (n_targets && !dests->u.arr.elem) { free(dests); plugmod_resp_free(map); return NULL; }
  for (size_t k = 0; k < n_targets; k++) {
    dests->u.arr.elem[k].type = PLUGMOD_RESPT_BULK;
    dests->u.arr.elem[k].u.s = strdup(target_extensions[k] ? target_extensions[k] : "");
  }
  e[5].type = PLUGMOD_RESPT_ARRAY; e[5].u.arr = dests->u.arr; free(dests);
  e[6].type = PLUGMOD_RESPT_BULK; e[6].u.s = strdup("call_id");
  e[7].type = PLUGMOD_RESPT_BULK; e[7].u.s = strdup(call_id ? call_id : "");
  if (!e[0].u.s || !e[1].u.s || !e[2].u.s || !e[3].u.s || !e[4].u.s || !e[6].u.s || !e[7].u.s) {
    plugmod_resp_free(map);
    return NULL;
  }
  return map;
}

/* Apply trunk override: from current_trunks (n_current), build new list ordered/filtered by names (string or array).
 * Returns new array and count; caller frees the array (not the config_trunk*). */
static config_trunk **apply_trunk_override(config_trunk **current_trunks, size_t n_current,
  plugmod_resp_object *trunk_val, size_t *out_n) {
  *out_n = 0;
  if (!trunk_val || !current_trunks) return NULL;
  size_t names_cap = 64;
  const char **names = malloc(names_cap * sizeof(const char *));
  if (!names) return NULL;
  size_t n_names = 0;
  if (trunk_val->type == PLUGMOD_RESPT_BULK || trunk_val->type == PLUGMOD_RESPT_SIMPLE) {
    if (trunk_val->u.s && trunk_val->u.s[0]) {
      names[n_names++] = trunk_val->u.s;
    }
  } else if (trunk_val->type == PLUGMOD_RESPT_ARRAY) {
    for (size_t i = 0; i < trunk_val->u.arr.n && n_names < names_cap; i++) {
      plugmod_resp_object *e = &trunk_val->u.arr.elem[i];
      const char *s = (e->type == PLUGMOD_RESPT_BULK || e->type == PLUGMOD_RESPT_SIMPLE) ? e->u.s : NULL;
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
    if (!plugmod_has_event(name, "call.dialout")) continue;
    plugmod_resp_object *request_map = build_dialout_request_map(source_ext, current_destination, call_id, current_trunks, n_current);
    if (!request_map) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "call.dialout", 1, (const plugmod_resp_object *const *)&request_map, &r) != 0 || !r) {
      plugmod_resp_free(request_map);
      continue;
    }
    plugmod_resp_free(request_map);
    if (r->type != PLUGMOD_RESPT_ARRAY || (r->u.arr.n & 1)) {
      log_error("plugin %s: call.dialout returned invalid response (not a map)", name);
      plugmod_resp_free(r);
      continue;
    }
    const char *action_str = plugmod_resp_map_get_string(r, "action");
    if (!action_str) {
      log_error("plugin %s: call.dialout response missing action", name);
      plugmod_resp_free(r);
      continue;
    }
    if (strcasecmp(action_str, "reject") == 0) {
      *out_action = 1;
      plugmod_resp_object *code_val = plugmod_resp_map_get(r, "reject_code");
      if (code_val && code_val->type == PLUGMOD_RESPT_INT) {
        *out_reject_code = (int)code_val->u.i;
        if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      }
      plugmod_resp_free(r);
      free(current_destination);
      free(current_trunks);
      return;
    }
    if (strcasecmp(action_str, "accept") == 0) {
      *out_action = 2;
      const char *d = plugmod_resp_map_get_string(r, "destination");
      if (d && d[0]) {
        free(current_destination);
        current_destination = strdup(d);
      }
      plugmod_resp_object *trunk_val = plugmod_resp_map_get(r, "trunk");
      if (trunk_val) {
        trunk_override_was_set = 1;
        config_trunk **new_trunks = apply_trunk_override(current_trunks, n_current, trunk_val, &n_current);
        free(current_trunks);
        current_trunks = new_trunks;
      }
      plugmod_resp_free(r);
      continue;
    }
    plugmod_resp_free(r);
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
    if (!plugmod_has_event(name, "call.dialin")) continue;
    plugmod_resp_object *request_map = build_dialin_request_map(trunk_name, did, target_extensions, n_targets, call_id);
    if (!request_map) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "call.dialin", 1, (const plugmod_resp_object *const *)&request_map, &r) != 0 || !r) {
      plugmod_resp_free(request_map);
      continue;
    }
    plugmod_resp_free(request_map);
    if (r->type != PLUGMOD_RESPT_ARRAY || (r->u.arr.n & 1)) {
      plugmod_resp_free(r);
      continue;
    }
    const char *action_str = plugmod_resp_map_get_string(r, "action");
    if (action_str && strcasecmp(action_str, "reject") == 0) {
      *out_action = 1;
      plugmod_resp_object *code_val = plugmod_resp_map_get(r, "reject_code");
      if (code_val && code_val->type == PLUGMOD_RESPT_INT) {
        *out_reject_code = (int)code_val->u.i;
        if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      }
      plugmod_resp_free(r);
      return;
    }
    if (action_str && strcasecmp(action_str, "accept") == 0) {
      plugmod_resp_object *dests_val = plugmod_resp_map_get(r, "destinations");
      if (dests_val && dests_val->type == PLUGMOD_RESPT_ARRAY) {
        size_t n = dests_val->u.arr.n;
        if (n == 0) {
          log_error("plugin %s: call.dialin accept with empty destinations array, treating as continue", name);
        } else {
          char **targets = (char **)malloc(n * sizeof(char *));
          if (targets) {
            for (size_t j = 0; j < n; j++) {
              plugmod_resp_object *elem = &dests_val->u.arr.elem[j];
              targets[j] = (elem->type == PLUGMOD_RESPT_BULK || elem->type == PLUGMOD_RESPT_SIMPLE) && elem->u.s
                ? strdup(elem->u.s) : NULL;
            }
            *out_targets = targets;
            *out_n = n;
            *out_action = 2;
          }
          plugmod_resp_free(r);
          return;
        }
      }
    }
    plugmod_resp_free(r);
  }
}

size_t plugin_count(void) {
  return plugmod_count();
}

const char *plugin_name_at(size_t i) {
  return plugmod_name_at(i);
}
