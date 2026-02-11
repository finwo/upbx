/*
 * Generic plugin module: spawn processes, RESP over stdio, discovery and events.
 * No application-specific types. Reusable outside upbx.
 */
#ifndef PLUGINMODULE_PLUGIN_H
#define PLUGINMODULE_PLUGIN_H

#include <stddef.h>
#include "RespModule/resp.h"

/* Callback invoked after discovery (and when config is resent without restart). */
typedef void (*plugmod_after_discovery_fn)(const char *plugin_name, void *user);

/* One plugin to start: name and exec path (passed to sh -c). config_hash: 0 = do not compare for "config updated".
 * restart_on_update: 0 = on config change restart only if exec changed else resend config; 1 = always restart. */
typedef struct plugmod_config_item {
  const char *name;
  const char *exec;
  unsigned long long config_hash;
  int restart_on_update;
} plugmod_config_item;

/* Start plugins. discovery_cmd: sent to discover all methods the plugin supports (e.g. "command"). Discovery skipped if NULL.
 * after_discovery_cb: optional; called after each plugin's discovery (and when config is resent without restart). */
void plugmod_start(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd,
  plugmod_after_discovery_fn after_discovery_cb, void *after_discovery_user);

void plugmod_stop(void);

/* Stop one plugin by name: send SIGINT, mark STOPPING. Non-blocking. */
void plugmod_stop_plugin(const char *name);

/* Reap STOPPING plugins: if 30s elapsed since SIGINT, send SIGKILL and remove. Call each main-loop iteration. */
void plugmod_tick(void);

/* Start one plugin (spawn, discovery). discovery_cmd must be set (e.g. by prior plugmod_start or plugmod_sync). Returns 0 on success. */
int plugmod_start_plugin(const char *name, const char *exec, unsigned long long config_hash, int restart_on_update);

/* Sync plugins to config: tick, then stop removed/changed, start added. Stores discovery_cmd and after_discovery callback. */
void plugmod_sync(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd,
  plugmod_after_discovery_fn after_discovery_cb, void *after_discovery_user);

/* Invoke method; response is consumed and discarded. Returns 0 on success. */
int plugmod_invoke(const char *plugin_name, const char *method, int argc, const resp_object *const *argv);

/* Invoke and return decoded response. Caller must resp_free(*out). Returns 0 on success. */
int plugmod_invoke_response(const char *plugin_name, const char *method, int argc, const resp_object *const *argv,
  resp_object **out);

/* Check if plugin supports the given method (case-insensitive). Same list used for events and methods. */
int plugmod_has_method(const char *plugin_name, const char *method_name);

void plugmod_notify_event(const char *event_name, int argc, const resp_object *const *argv);

size_t plugmod_count(void);
const char *plugmod_name_at(size_t i);

#endif
