#ifndef UPBX_CONFIG_H
#define UPBX_CONFIG_H

#include <stddef.h>

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
} config_trunk;

typedef struct {
  char *number;   /* extension number from section ext:N */
  char *name;    /* optional display name */
  char *secret;
} config_extension;

struct upbx_config {
  int locality;       /* 0 = disabled */
  int daemonize;      /* 0 or 1 */
  char *listen;       /* SIP listen address, e.g. "0.0.0.0:5060" */
  int rtp_port_low;   /* RTP relay port range (from rtp_ports low-high; default 10000-20000) */
  int rtp_port_high;
  config_plugin *plugins;
  size_t plugin_count;

  config_trunk *trunks;
  size_t trunk_count;

  config_extension *extensions;
  size_t extension_count;
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

#endif
