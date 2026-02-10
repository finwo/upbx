/*
 * Plugin system: spawn external processes, communicate via RESP over stdio.
 * Discovery via COMMAND. Event prefixes: EXTENSION., TRUNK., CALL.
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

/* Invoke plugin method: send RESP array (method, arg0, arg1, ...), read response.
 * Returns 0 on success, -1 on transport error. Response is consumed/discarded. */
int plugin_invoke(const char *plugin_name, const char *method, int argc, const plugmod_resp_object *const *argv);

/* Check if plugin has registered an event (e.g. "EXTENSION.REGISTER", "CALL.DIALOUT"). */
int plugin_has_event(const char *plugin_name, const char *event_name);

/* Notify all plugins that have this event. Sends RESP array (event_name, arg0, arg1, ...).
 * Each plugin's response is read and discarded. */
void plugin_notify_event(const char *event_name, int argc, const plugmod_resp_object *const *argv);

/* --- Query events: plugin response alters PBX behavior --- */

/* EXTENSION.REGISTER: after parsing extension/trunk, before or instead of built-in auth.
 * Args: extension_num, trunk_name, from_user.
 * Returns: *out_allow: -1 = CONTINUE, 0 = DENY, 1 = ALLOW. If ALLOW, *out_custom may be set (caller frees). */
void plugin_query_register(const char *extension_num, const char *trunk_name, const char *from_user,
  int *out_allow, char **out_custom);

/* CALL.DIALOUT: outgoing call from extension. Args: source_ext, source_trunk, destination, call_id.
 * Returns: 0 = no-edit, 1 = reject (*out_reject_code), 2 = allow (*out_target_override = new target or NULL to use destination). Caller frees *out_target_override. */
void plugin_query_dialout(const char *source_ext, const char *source_trunk, const char *destination, const char *call_id,
  int *out_action, int *out_reject_code, char **out_target_override);

/* CALL.DIALIN: incoming call from trunk. Args: trunk_name, did, then N extension numbers (targets), then call_id.
 * argc = 3 + n_targets (trunk, did, ext1, ext2, ..., call_id). Returns: 0 = dont-care, 1 = reject (*out_reject_code), 2 = alter (*out_targets = new list of extension numbers, *out_n, caller frees). */
void plugin_query_dialin(const char *trunk_name, const char *did, const char **target_extensions, size_t n_targets, const char *call_id,
  int *out_action, int *out_reject_code, char ***out_targets, size_t *out_n);

/* Number of loaded plugins. */
size_t plugin_count(void);

/* Name of plugin at index i (0 .. plugin_count()-1). */
const char *plugin_name_at(size_t i);

#endif
