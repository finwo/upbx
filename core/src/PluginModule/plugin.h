/*
 * Generic plugin module: spawn processes, RESP over stdio, discovery and events.
 * No application-specific types. Reusable outside upbx.
 */
#ifndef PLUGINMODULE_PLUGIN_H
#define PLUGINMODULE_PLUGIN_H

#include <stddef.h>

/* One plugin to start: name and exec path (passed to sh -c). config_hash: 0 = do not compare for "config updated". */
typedef struct plugmod_config_item {
  const char *name;
  const char *exec;
  unsigned long long config_hash;
} plugmod_config_item;

#define PLUGMOD_RESPT_SIMPLE  0
#define PLUGMOD_RESPT_ERROR  1
#define PLUGMOD_RESPT_BULK   2
#define PLUGMOD_RESPT_INT    3
#define PLUGMOD_RESPT_ARRAY  4

/* RESP response object for parsing plugin responses. Call plugmod_resp_free. */
typedef struct plugmod_resp_object plugmod_resp_object;
struct plugmod_resp_object {
  int type;  /* PLUGMOD_RESPT_* */
  union {
    char *s;
    long long i;
    struct { plugmod_resp_object *elem; size_t n; } arr;
  } u;
};

void plugmod_resp_free(plugmod_resp_object *o);

/* Map helper: given a response array interpreted as a map (even-length: key, value, key, value, ...),
 * return a pointer to the value element for the given key, or NULL. Returned pointer is into the array;
 * valid until the response is freed. */
plugmod_resp_object *plugmod_resp_map_get(const plugmod_resp_object *o, const char *key);

/* Map + key → value as string (BULK/SIMPLE), or NULL. Valid until response freed. */
const char *plugmod_resp_map_get_string(const plugmod_resp_object *o, const char *key);

/* Start plugins. discovery_cmd: sent to discover methods/events (e.g. "COMMAND").
 * event_prefixes: array of prefixes; discovery strings starting with any of these are events (e.g. "EXTENSION.", "TRUNK.", "CALL.").
 * n_event_prefixes: number of prefixes; 0 = none (no events). Discovery skipped if discovery_cmd is NULL. */
void plugmod_start(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd, const char **event_prefixes, size_t n_event_prefixes);

void plugmod_stop(void);

/* Stop one plugin by name: send SIGINT, mark STOPPING. Non-blocking. */
void plugmod_stop_plugin(const char *name);

/* Reap STOPPING plugins: if 30s elapsed since SIGINT, send SIGKILL and remove. Call each main-loop iteration. */
void plugmod_tick(void);

/* Start one plugin (spawn, discovery). discovery_cmd and event_prefixes must be set (e.g. by prior plugmod_start or plugmod_sync). config_hash stored for later comparison; 0 = ignore. Returns 0 on success. */
int plugmod_start_plugin(const char *name, const char *exec, unsigned long long config_hash);

/* Sync plugins to config: tick, then stop removed/changed, start added. Stores discovery_cmd and event_prefixes for plugmod_start_plugin. */
void plugmod_sync(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd, const char **event_prefixes, size_t n_event_prefixes);

/* Invoke method; response is consumed and discarded. Returns 0 on success. */
int plugmod_invoke(const char *plugin_name, const char *method, int argc, const plugmod_resp_object *const *argv);

/* Invoke and return decoded response. Caller must plugmod_resp_free(*out). Returns 0 on success. */
int plugmod_invoke_response(const char *plugin_name, const char *method, int argc, const plugmod_resp_object *const *argv,
  plugmod_resp_object **out);

int plugmod_has_event(const char *plugin_name, const char *event_name);

void plugmod_notify_event(const char *event_name, int argc, const plugmod_resp_object *const *argv);

size_t plugmod_count(void);
const char *plugmod_name_at(size_t i);

#endif
