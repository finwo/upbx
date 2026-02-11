/*
 * Plugin system: spawn external processes, communicate via RESP over stdio.
 * Discovery via command. Event prefixes: extension., trunk., call.
 * Started from AppModule after config load.
 */
#ifndef UPBX_APPMODULE_PLUGIN_H
#define UPBX_APPMODULE_PLUGIN_H

#include "config.h"
#include "PluginModule/plugin.h"

/* Start all plugins from config (spawn process, discovery). Call after config_load. */
void plugin_start(upbx_config *cfg);

/* Stop all plugins (close pipes, kill processes). */
void plugin_stop(void);

/* Sync plugins with live config: config_sections_list (plugin:*), compare section hash for changes, call plugmod_sync. Call on startup and each daemon iteration. */
void plugin_sync(void);

/* Invoke plugin method: send RESP array (method, arg0, arg1, ...), read response.
 * Returns 0 on success, -1 on transport error. Response is consumed/discarded. */
int plugin_invoke(const char *plugin_name, const char *method, int argc, const resp_object *const *argv);

/* Check if plugin has registered an event (e.g. "extension.register", "call.dialout"). */
int plugin_has_event(const char *plugin_name, const char *event_name);

/* Notify all plugins that have this event. Sends RESP array (event_name, arg0, arg1, ...).
 * Each plugin's response is read and discarded. */
void plugin_notify_event(const char *event_name, int argc, const resp_object *const *argv);

/* Query events: plugin response alters PBX behavior */

/* extension.register: after parsing extension/trunk, before or instead of built-in auth.
 * Input: one map (extension, trunk, from_user). Response: map with action = reject | accept | continue.
 * Returns: *out_allow: -1 = continue, 0 = reject, 1 = accept. */
void plugin_query_register(const char *extension_num, const char *trunk_name, const char *from_user,
  int *out_allow);

/* call.dialout: outgoing call from extension. Input: one map (source_ext, destination, call_id, trunks). Response: map with action = reject | accept; reject_code (int) when reject; optional destination, trunk when accept. Returns: 0 = no-edit, 1 = reject (*out_reject_code), 2 = accept (*out_target_override, *out_trunk_override, *out_trunk_override_n). Caller frees *out_target_override and *out_trunk_override (and each element). */
void plugin_query_dialout(upbx_config *cfg, const char *source_ext, const char *destination, const char *call_id,
  config_trunk **initial_trunks, size_t n_initial_trunks,
  int *out_action, int *out_reject_code, char **out_target_override,
  char ***out_trunk_override, int *out_trunk_override_n);

/* call.dialin: incoming call from trunk. Input: one map (trunk, did, destinations, call_id). Response: map with action = reject | continue | accept; reject_code (int) when reject; optional destinations (array) when accept. Returns: 0 = dont-care, 1 = reject (*out_reject_code), 2 = accept with override (*out_targets, *out_n; caller frees). */
void plugin_query_dialin(const char *trunk_name, const char *did, const char **target_extensions, size_t n_targets, const char *call_id,
  int *out_action, int *out_reject_code, char ***out_targets, size_t *out_n);

/* Number of loaded plugins. */
size_t plugin_count(void);

/* Name of plugin at index i (0 .. plugin_count()-1). */
const char *plugin_name_at(size_t i);

#endif
