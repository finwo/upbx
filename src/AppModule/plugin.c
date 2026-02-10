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

int plugin_invoke(const char *plugin_name, const char *method, int argc, const char **argv) {
  return plugmod_invoke(plugin_name, method, argc, argv);
}

int plugin_has_event(const char *plugin_name, const char *event_name) {
  return plugmod_has_event(plugin_name, event_name);
}

void plugin_notify_event(const char *event_name, int argc, const char **argv) {
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
  const char *argv[] = { extension_num, trunk_name, from_user ? from_user : "" };
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

void plugin_query_dialout(const char *source_ext, const char *source_trunk, const char *destination, const char *call_id,
  int *out_action, int *out_reject_code, char **out_target_override) {
  *out_action = 0; /* no-edit */
  *out_reject_code = 403;
  *out_target_override = NULL;
  const char *argv[] = { source_ext ? source_ext : "", source_trunk ? source_trunk : "", destination ? destination : "", call_id ? call_id : "" };
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_event(name, "CALL.DIALOUT")) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "CALL.DIALOUT", 4, argv, &r) != 0 || !r)
      continue;
    const char *first = resp_first_string(r);
    if (!first) { plugmod_resp_free(r); continue; }
    if (strcasecmp(first, "REJECT") == 0) {
      *out_action = 1;
      const char *code_str = resp_second_string(r);
      if (code_str) *out_reject_code = atoi(code_str);
      if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      plugmod_resp_free(r);
      return;
    }
    if (strcasecmp(first, "ALLOW") == 0) {
      *out_action = 2;
      const char *target = resp_second_string(r);
      if (target && target[0]) *out_target_override = strdup(target);
      plugmod_resp_free(r);
      return;
    }
    plugmod_resp_free(r);
  }
}

void plugin_query_dialin(const char *trunk_name, const char *did, const char **target_extensions, size_t n_targets, const char *call_id,
  int *out_action, int *out_reject_code, char ***out_targets, size_t *out_n) {
  *out_action = 0; /* dont-care */
  *out_reject_code = 403;
  *out_targets = NULL;
  *out_n = 0;
  /* Build argv: trunk, did, ext1, ext2, ..., call_id */
  size_t argc = 3 + n_targets; /* trunk, did, [exts], call_id */
  char **argv = (char **)malloc((argc + 1) * sizeof(char *));
  if (!argv) return;
  argv[0] = (char *)(trunk_name ? trunk_name : "");
  argv[1] = (char *)(did ? did : "");
  for (size_t k = 0; k < n_targets; k++)
    argv[2 + k] = (char *)(target_extensions[k] ? target_extensions[k] : "");
  argv[2 + n_targets] = (char *)(call_id ? call_id : "");
  for (size_t i = 0; i < plugmod_count(); i++) {
    const char *name = plugmod_name_at(i);
    if (!plugmod_has_event(name, "CALL.DIALIN")) continue;
    plugmod_resp_object *r = NULL;
    if (plugmod_invoke_response(name, "CALL.DIALIN", (int)argc, (const char **)argv, &r) != 0 || !r)
      continue;
    const char *first = resp_first_string(r);
    if (!first) { plugmod_resp_free(r); continue; }
    if (strcasecmp(first, "REJECT") == 0) {
      *out_action = 1;
      const char *code_str = resp_second_string(r);
      if (code_str) *out_reject_code = atoi(code_str);
      if (*out_reject_code < 100 || *out_reject_code > 699) *out_reject_code = 403;
      plugmod_resp_free(r);
      free(argv);
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
      free(argv);
      return;
    }
    plugmod_resp_free(r);
  }
  free(argv);
}

size_t plugin_count(void) {
  return plugmod_count();
}

const char *plugin_name_at(size_t i) {
  return plugmod_name_at(i);
}
