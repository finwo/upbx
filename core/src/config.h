#ifndef UPBX_CONFIG_H
#define UPBX_CONFIG_H

#include <stddef.h>
#include "RespModule/resp.h"

/* Global config instance - stored as resp_object map */
extern resp_object *global_cfg;

/* Pending config for double-buffer reload */
extern resp_object *pending_cfg;

/* Initialize pending config */
void config_pending_init(void);

/* Swap active and pending configs */
void config_swap(void);

/* Trigger config reload on next scheduler cycle */
void config_trigger_reload(void);

/* Check if config reload is pending */
int config_is_reload_pending(void);

/* Reload config from file (double-buffer swap) */
int config_reload(void);

/* Lock/unlock config (no-ops in single-threaded PT system) */
void config_lock(void);
void config_unlock(void);

/* Load config from file into given resp_object. Returns 0 on success, -1 on file error, >0 line number. */
int config_load(resp_object *cfg, const char *path);

/* After config_load returned >0, copy the section/key that caused the parse error (for logging). */
void config_last_parse_error(char *section_out, size_t section_size, char *key_out, size_t key_size);

/* Compile trunk rewrite patterns (POSIX regex). Call after config_load. Returns 0 on success, -1 on compile error. */
int config_compile_trunk_rewrites(resp_object *cfg);

/* Apply trunk rewrite patterns to destination number. Returns 1 if rewritten, 0 if no match. */
int config_rewrite_destination(const char *trunk_name, const char *input, char *output, size_t out_size);

/* Initialize config to defaults */
void config_init(void);

/* Free config (uses resp_free) */
void config_free(resp_object *cfg);

/* Set/get config file path (used by default getters). Set once at startup. */
void config_set_path(const char *path);
const char *config_get_path(void);

/* Path-taking (low-level). Load fresh from file, returns COPIES (caller must free). */
resp_object *config_sections_list_path(const char *path);
resp_object *config_section_get_path(const char *path, const char *section);
resp_object *config_key_get_path(const char *path, const char *section, const char *key);

/* Default getters (use stored path). Load fresh from file, returns COPIES (caller must free). */
resp_object *config_sections_list(void);
resp_object *config_section_get(const char *section);
resp_object *config_key_get(const char *section, const char *key);

/* Convenience getters for common fields (return copies, caller must free) */
char *config_get_listen(void);
char *config_get_rtp_mode(void);
char *config_get_rtp_socket(void);
char *config_get_rtp_advertise_addr(void);
int config_get_rtp_port_low(void);
int config_get_rtp_port_high(void);
int config_get_locality(void);
int config_get_daemonize(void);
int config_get_cross_group_calls(void);

/* Get extension/trunk/plugin by number/name - returns pointer into global_cfg, caller does NOT free */
resp_object *config_get_extension(const char *number);

/* Get arrays of extensions/trunks/plugins - returns new array with COPIES, caller must free result */
resp_object *config_get_extensions(void);
resp_object *config_get_trunks(void);
resp_object *config_get_plugins(void);

/* Get emergency section - returns pointer into global_cfg, caller does NOT free */
resp_object *config_get_emergency(void);

#endif