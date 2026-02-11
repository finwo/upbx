#ifndef UPBX_CONFIG_H
#define UPBX_CONFIG_H

#include <stddef.h>
#include "RespModule/resp.h"

typedef struct upbx_config upbx_config;

typedef struct {
  char *name;
  char *exec;
} config_plugin;

typedef struct {
  char *pattern;
  char *replace;
} config_rewrite;

typedef struct {
  char *name;
  char *host;
  char *port;
  char *username;         /* Username for trunk registration to upstream */
  char *password;         /* Password for trunk registration */
  char **dids;
  size_t did_count;
  char *cid;              /* Outgoing caller ID number */
  char *cid_name;         /* Optional caller ID display name */
  config_rewrite *rewrites;
  size_t rewrite_count;
  void *rewrite_regex;    /* internal: array of compiled regex_t (one per rewrite), set by config_compile_trunk_rewrites */
  int overflow_timeout;   /* seconds, 0 = disabled */
  char *overflow_strategy;/* "none", "busy", "include", or "redirect" (default "none" if not set) */
  char *overflow_target; /* Number for "include" or "redirect" strategy */
  char *user_agent;       /* Custom User-Agent for trunk registration */
  char *group_prefix;     /* Group prefix for locality-based trunk assignment (e.g. "1234" for locality 3) */
  int filter_incoming;    /* 0 (default) = accept any matching extension; 1 = only accept calls to registered DIDs */
} config_trunk;

typedef struct {
  char *number;   /* extension number from section ext:N */
  char *name;    /* optional display name */
  char *secret;
} config_extension;

typedef struct {
  char *username;     /* from section name; "*" = anonymous */
  char *secret;       /* password */
  char **permits;     /* array of permit patterns (e.g. "metrics.*") */
  size_t permit_count;
} config_api_user;

typedef struct {
  char *listen;         /* e.g. "127.0.0.1:6380"; NULL = API disabled */
  config_api_user *users;
  size_t user_count;
} config_api;

struct upbx_config {
  int locality;       /* 0 = disabled */
  int daemonize;      /* 0 or 1 */
  int cross_group_calls; /* 1 = allow ext-to-ext across groups (default), 0 = block */
  char *listen;       /* SIP listen address, e.g. "0.0.0.0:5060" */
  int rtp_port_low;   /* RTP relay port range (from rtp_ports low-high; default 10000-20000) */
  int rtp_port_high;
  char **emergency;   /* Numbers that always route externally (e.g. "911") */
  size_t emergency_count;
  config_plugin *plugins;
  size_t plugin_count;

  config_trunk *trunks;
  size_t trunk_count;

  config_extension *extensions;
  size_t extension_count;

  config_api api;
};

/* Load config from file. Returns 0 on success, -1 on file error, >0 line number of first parse error. */
int config_load(upbx_config *cfg, const char *path);

/* After config_load returned >0, copy the section/key that caused the parse error (for logging). */
void config_last_parse_error(char *section_out, size_t section_size, char *key_out, size_t key_size);

/* Compile trunk rewrite patterns (POSIX regex). Call after config_load. Returns 0 on success, -1 on compile error. */
int config_compile_trunk_rewrites(upbx_config *cfg);

/* Free all allocated strings and arrays in cfg. Does not free cfg itself. */
void config_free(upbx_config *cfg);

/* Initialize cfg to defaults (zeros). */
void config_init(upbx_config *cfg);

/* Live config API (re-read file each call; no cache). Caller frees with resp_free.
 * Values are unescaped (\\ -> \, \@ -> @). Raw value starting with @ is a reference:
 * @section or @section.key. Reference specs are used as-is for lookup; no normalization. */

/* Set/get config file path (used by default getters). Set once at startup. */
void config_set_path(const char *path);
const char *config_get_path(void);

/* Path-taking (low-level). Return NULL on error or missing path. */
resp_object *config_sections_list_path(const char *path);
resp_object *config_section_get_path(const char *path, const char *section);
resp_object *config_key_get_path(const char *path, const char *section, const char *key);

/* Default getters (use stored path). Return NULL if path not set or on error. */
resp_object *config_sections_list(void);
resp_object *config_section_get(const char *section);
resp_object *config_key_get(const char *section, const char *key);

#endif
