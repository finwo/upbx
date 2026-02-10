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

static const char *event_prefixes[] = { "EXTENSION.", "TRUNK.", "CALL." };
#define N_EVENT_PREFIXES (sizeof(event_prefixes) / sizeof(event_prefixes[0]))

/* Start all plugins from config; uses COMMAND for discovery and EXTENSION./TRUNK./CALL. events. */
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
    n++;
  }
  plugmod_start(configs, n, "COMMAND", event_prefixes, N_EVENT_PREFIXES);
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

static const char *resp_first_string(plugmod_resp_object *o) {
  if (!o) return NULL;
  if (o->type == PLUGMOD_RESPT_SIMPLE || o->type == PLUGMOD_RESPT_ERROR || o->type == PLUGMOD_RESPT_BULK)
    return o->u.s;
  if (o->type == PLUGMOD_RESPT_ARRAY && o->u.arr.n > 0) {
    plugmod_resp_object *e = &o->u.arr.elem[0];
    if (e->type == PLUGMOD_RESPT_SIMPLE || e->type == PLUGMOD_RESPT_BULK)
      return e->u.s;
  }
  return NULL;
}

static const char *resp_second_string(plugmod_resp_object *o) {
  if (!o || o->type != PLUGMOD_RESPT_ARRAY || o->u.arr.n < 2) return NULL;
  plugmod_resp_object *e = &o->u.arr.elem[1];
  if (e->type == PLUGMOD_RESPT_SIMPLE || e->type == PLUGMOD_RESPT_BULK)
    return e->u.s;
  return NULL;
}

void plugin_query_register(const char *extension_num, const char *trunk_name, const char *from_user,
  int *out_allow, char **out_custom) {
  *out_allow = -1; /* CONTINUE */
  *out_custom = NULL;
  const plugmod_resp_object a0 = { .type = PLUGMOD_RESPT_BULK, .u = { .s = (char *)(extension_num ? extension_num : "") } };
  const plugmod_resp_object a1 = { .type = PLUGMOD_RESPT_BULK, .u = { .s = (char *)(trunk_name ? trunk_name : "") } };
  const plugmod_resp_object a2 = { .type = PLUGMOD_RESPT_BULK, .u = { .s = (char *)(from_user ? from_user : "") } };
  const plugmod_resp_object *argv[] = { &a0, &a1, &a2 };
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_event(name, "EXTENSION.REGISTER")) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "EXTENSION.REGISTER", 3, argv, &r) != 0 || !r)
      continue;
    const char *first = resp_first_string(r);
    if (first) {
      if (strcasecmp(first, "DENY") == 0) {
        *out_allow = 0;
        plugmod_resp_free(r);
        return;
      }
      if (strcasecmp(first, "ALLOW") == 0) {
        *out_allow = 1;
        const char *custom = resp_second_string(r);
        if (custom && custom[0])
          *out_custom = strdup(custom);
        plugmod_resp_free(r);
        return;
      }
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
    if (!plugmod_has_event(name, "CALL.DIALOUT")) continue;
    plugmod_resp_object *request_map = build_dialout_request_map(source_ext, current_destination, call_id, current_trunks, n_current);
    if (!request_map) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "CALL.DIALOUT", 1, (const plugmod_resp_object *const *)&request_map, &r) != 0 || !r) {
      plugmod_resp_free(request_map);
      continue;
    }
    plugmod_resp_free(request_map);
    if (r->type != PLUGMOD_RESPT_ARRAY || (r->u.arr.n & 1)) {
      log_error("plugin %s: CALL.DIALOUT returned invalid response (not a map)", name);
      plugmod_resp_free(r);
      continue;
    }
    const char *action_str = plugmod_resp_map_get_string(r, "action");
    if (!action_str) {
      log_error("plugin %s: CALL.DIALOUT response missing action", name);
      plugmod_resp_free(r);
      continue;
    }
    if (strcasecmp(action_str, "REJECT") == 0) {
      *out_action = 1;
      const char *code_str = plugmod_resp_map_get_string(r, "reject_code");
      if (code_str) *out_reject_code = atoi(code_str);
      if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      plugmod_resp_free(r);
      free(current_destination);
      free(current_trunks);
      return;
    }
    if (strcasecmp(action_str, "ALLOW") == 0) {
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
  *out_action = 0; /* dont-care */
  *out_reject_code = 403;
  *out_targets = NULL;
  *out_n = 0;
  /* Build argv: trunk, did, ext1, ext2, ..., call_id */
  size_t argc = 3 + n_targets; /* trunk, did, [exts], call_id */
  plugmod_resp_object *objs = (plugmod_resp_object *)malloc(argc * sizeof(plugmod_resp_object));
  if (!objs) return;
  plugmod_resp_object **ptrs = (plugmod_resp_object **)malloc(argc * sizeof(plugmod_resp_object *));
  if (!ptrs) { free(objs); return; }
  objs[0].type = PLUGMOD_RESPT_BULK;
  objs[0].u.s = (char *)(trunk_name ? trunk_name : "");
  objs[1].type = PLUGMOD_RESPT_BULK;
  objs[1].u.s = (char *)(did ? did : "");
  for (size_t k = 0; k < n_targets; k++) {
    objs[2 + k].type = PLUGMOD_RESPT_BULK;
    objs[2 + k].u.s = (char *)(target_extensions[k] ? target_extensions[k] : "");
  }
  objs[2 + n_targets].type = PLUGMOD_RESPT_BULK;
  objs[2 + n_targets].u.s = (char *)(call_id ? call_id : "");
  for (size_t i = 0; i < argc; i++)
    ptrs[i] = &objs[i];
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_event(name, "CALL.DIALIN")) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "CALL.DIALIN", (int)argc, (const plugmod_resp_object *const *)ptrs, &r) != 0 || !r)
      continue;
    const char *first = resp_first_string(r);
    if (!first) { plugmod_resp_free(r); continue; }
    if (strcasecmp(first, "REJECT") == 0) {
      *out_action = 1;
      const char *code_str = resp_second_string(r);
      if (code_str) *out_reject_code = atoi(code_str);
      if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      plugmod_resp_free(r);
      free(ptrs);
      free(objs);
      return;
    }
    if (strcasecmp(first, "ALTER") == 0 && r->type == PLUGMOD_RESPT_ARRAY && r->u.arr.n > 1) {
      size_t n = r->u.arr.n - 1;
      char **targets = (char **)malloc(n * sizeof(char *));
      if (targets) {
        for (size_t j = 1; j < r->u.arr.n; j++) {
          plugmod_resp_object *e = &r->u.arr.elem[j];
          targets[j - 1] = (e->type == PLUGMOD_RESPT_SIMPLE || e->type == PLUGMOD_RESPT_BULK) && e->u.s
            ? strdup(e->u.s) : NULL;
        }
        *out_targets = targets;
        *out_n = n;
        *out_action = 2;
      }
      plugmod_resp_free(r);
      free(ptrs);
      free(objs);
      return;
    }
    plugmod_resp_free(r);
  }
  free(ptrs);
  free(objs);
}

size_t plugin_count(void) {
  return plugmod_count();
}

const char *plugin_name_at(size_t i) {
  return plugmod_name_at(i);
}
