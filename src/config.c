#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>

#include "benhoyt/inih.h"
#include "rxi/log.h"
#include "config.h"

#define STRDUP(s) ((s) ? strdup(s) : NULL)

/* Copy src into dest, trimming leading/trailing whitespace; dest is null-terminated. Returns dest. */
static char *trim_copy(char *dest, size_t dest_size, const char *src) {
  if (!dest || dest_size == 0) return dest;
  dest[0] = '\0';
  if (!src) return dest;
  while (*src == ' ' || *src == '\t' || *src == '\r' || *src == '\n') src++;
  const char *end = src;
  while (*end) end++;
  while (end > src && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) end--;
  size_t len = (size_t)(end - src);
  if (len >= dest_size) len = dest_size - 1;
  memcpy(dest, src, len);
  dest[len] = '\0';
  return dest;
}

static config_plugin *find_or_add_plugin(upbx_config *cfg, const char *name) {
  for (size_t i = 0; i < cfg->plugin_count; i++) {
    if (strcmp(cfg->plugins[i].name, name) == 0)
      return &cfg->plugins[i];
  }
  size_t old = cfg->plugin_count++;
  cfg->plugins = (config_plugin *)realloc(cfg->plugins, cfg->plugin_count * sizeof(config_plugin));
  if (!cfg->plugins) { cfg->plugin_count = old; return NULL; }
  config_plugin *p = &cfg->plugins[old];
  p->name = STRDUP(name);
  p->exec = NULL;
  if (!p->name) { cfg->plugin_count = old; return NULL; }
  return p;
}

static config_trunk *find_or_add_trunk(upbx_config *cfg, const char *name) {
  for (size_t i = 0; i < cfg->trunk_count; i++) {
    if (strcmp(cfg->trunks[i].name, name) == 0)
      return &cfg->trunks[i];
  }
  size_t old = cfg->trunk_count++;
  cfg->trunks = (config_trunk *)realloc(cfg->trunks, cfg->trunk_count * sizeof(config_trunk));
  if (!cfg->trunks) { cfg->trunk_count = old; return NULL; }
  config_trunk *t = &cfg->trunks[old];
  memset(t, 0, sizeof(*t));
  t->name = STRDUP(name);
  if (!t->name) { cfg->trunk_count = old; return NULL; }
  return t;
}

static int append_trunk_did(config_trunk *t, const char *value) {
  char **p = (char **)realloc(t->dids, (t->did_count + 1) * sizeof(char *));
  if (!p) return 0;
  t->dids = p;
  t->dids[t->did_count] = STRDUP(value);
  if (!t->dids[t->did_count]) return 0;
  t->did_count++;
  return 1;
}

static int append_trunk_rewrite(config_trunk *t, const char *pattern, const char *replace) {
  size_t n = t->rewrite_count++;
  t->rewrites = (config_rewrite *)realloc(t->rewrites, t->rewrite_count * sizeof(config_rewrite));
  if (!t->rewrites) { t->rewrite_count--; return 0; }
  t->rewrites[n].pattern = STRDUP(pattern);
  t->rewrites[n].replace = STRDUP(replace);
  if (!t->rewrites[n].pattern || !t->rewrites[n].replace) return 0;
  return 1;
}

static config_extension *find_or_add_extension(upbx_config *cfg, const char *number) {
  for (size_t i = 0; i < cfg->extension_count; i++) {
    if (strcmp(cfg->extensions[i].number, number) == 0)
      return &cfg->extensions[i];
  }
  size_t old = cfg->extension_count++;
  cfg->extensions = (config_extension *)realloc(cfg->extensions, cfg->extension_count * sizeof(config_extension));
  if (!cfg->extensions) { cfg->extension_count = old; return NULL; }
  config_extension *e = &cfg->extensions[old];
  memset(e, 0, sizeof(*e));
  e->number = STRDUP(number);
  if (!e->number) { cfg->extension_count = old; return NULL; }
  return e;
}

#define PREFIX_MATCH(sec, pre) (strncmp(sec, pre, sizeof(pre)-1) == 0 && (sec)[sizeof(pre)-1])
#define SECTION_TAIL(sec, pre) ((sec) + sizeof(pre) - 1)

/* Pair pattern with following replace in [trunk:...] */
static char *pending_rewrite_pattern;

#define TRIM_SECTION_SIZE 256
#define TRIM_NAME_SIZE    256
#define TRIM_VALUE_SIZE  2048

/* Last parse error (section/key) when handler returns 0; used for error reporting. */
static char last_parse_section[TRIM_SECTION_SIZE];
static char last_parse_key[TRIM_NAME_SIZE];

static void set_last_parse_error(const char *section, const char *name) {
  if (section) {
    size_t n = strlen(section);
    if (n >= sizeof(last_parse_section)) n = sizeof(last_parse_section) - 1;
    memcpy(last_parse_section, section, n);
    last_parse_section[n] = '\0';
  } else
    last_parse_section[0] = '\0';
  if (name) {
    size_t n = strlen(name);
    if (n >= sizeof(last_parse_key)) n = sizeof(last_parse_key) - 1;
    memcpy(last_parse_key, name, n);
    last_parse_key[n] = '\0';
  } else
    last_parse_key[0] = '\0';
}

static int handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  upbx_config *cfg = (upbx_config *)user;
  char sec[TRIM_SECTION_SIZE], key[TRIM_NAME_SIZE], val[TRIM_VALUE_SIZE];
  trim_copy(sec, sizeof(sec), section);
  trim_copy(key, sizeof(key), name);
  trim_copy(val, sizeof(val), value);

  if (strcmp(sec, "upbx") == 0) {
    if (strcmp(key, "locality") == 0) {
      cfg->locality = atoi(val);
      return 1;
    }
    if (strcmp(key, "daemonize") == 0) {
      cfg->daemonize = (atoi(val) != 0) ? 1 : 0;
      return 1;
    }
    if (strcmp(key, "listen") == 0) {
      free(cfg->listen);
      cfg->listen = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "rtp_ports") == 0) {
      int low = 0, high = 0;
      if (sscanf(val, "%d-%d", &low, &high) == 2 && low > 0 && high >= low) {
        cfg->rtp_port_low = low;
        cfg->rtp_port_high = high;
      }
      return 1;
    }
    log_warn("config line %d: unknown key '%s' in section '%s'", lineno, key, sec[0] ? sec : "(none)");
    return 1;
  }

  if (PREFIX_MATCH(sec, "plugin:")) {
    config_plugin *p = find_or_add_plugin(cfg, SECTION_TAIL(sec, "plugin:"));
    if (!p) { set_last_parse_error(sec, key); return 0; }
    if (strcmp(key, "exec") == 0) {
      free(p->exec);
      p->exec = STRDUP(val);
      return 1;
    }
    log_warn("config line %d: unknown key '%s' in section '%s'", lineno, key, sec[0] ? sec : "(none)");
    return 1;
  }

  if (PREFIX_MATCH(sec, "trunk:")) {
    config_trunk *t = find_or_add_trunk(cfg, SECTION_TAIL(sec, "trunk:"));
    if (!t) { set_last_parse_error(sec, key); return 0; }
    if (strcmp(key, "host") == 0) {
      free(t->host);
      t->host = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "port") == 0) {
      free(t->port);
      t->port = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "username") == 0) {
      free(t->username);
      t->username = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "password") == 0) {
      free(t->password);
      t->password = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "did") == 0) {
      if (!append_trunk_did(t, val)) { set_last_parse_error(sec, key); return 0; }
      return 1;
    }
    if (strcmp(key, "cid") == 0) {
      free(t->cid);
      t->cid = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "cid_name") == 0) {
      free(t->cid_name);
      t->cid_name = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "pattern") == 0) {
      free(pending_rewrite_pattern);
      pending_rewrite_pattern = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "replace") == 0) {
      if (pending_rewrite_pattern) {
        int ok = append_trunk_rewrite(t, pending_rewrite_pattern, val);
        free(pending_rewrite_pattern);
        pending_rewrite_pattern = NULL;
        if (!ok) { set_last_parse_error(sec, key); return 0; }
        return 1;
      }
      log_warn("config line %d: 'replace' without preceding 'pattern' in section '%s'", lineno, sec);
      return 1;
    }
    if (strcmp(key, "overflow_timeout") == 0) {
      t->overflow_timeout = atoi(val);
      return 1;
    }
    if (strcmp(key, "overflow_strategy") == 0) {
      free(t->overflow_strategy);
      t->overflow_strategy = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "overflow_target") == 0) {
      free(t->overflow_target);
      t->overflow_target = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "user_agent") == 0) {
      free(t->user_agent);
      t->user_agent = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "group") == 0) {
      free(t->group_prefix);
      t->group_prefix = STRDUP(val);
      return 1;
    }
    log_warn("config line %d: unknown key '%s' in section '%s'", lineno, key, sec);
    return 1;
  }

  if (PREFIX_MATCH(sec, "ext:")) {
    config_extension *e = find_or_add_extension(cfg, SECTION_TAIL(sec, "ext:"));
    if (!e) { set_last_parse_error(sec, key); return 0; }
    if (strcmp(key, "name") == 0) {
      free(e->name);
      e->name = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "secret") == 0) {
      free(e->secret);
      e->secret = STRDUP(val);
      return 1;
    }
    log_warn("config line %d: unknown key '%s' in section '%s'", lineno, key, sec);
    return 1;
  }

  log_warn("config line %d: unknown section '%s'", lineno, sec[0] ? sec : "(none)");
  return 1;
}

void config_init(upbx_config *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->rtp_port_low = 10000;
  cfg->rtp_port_high = 20000;
}

void config_free(upbx_config *cfg) {
  free(cfg->listen);

  for (size_t i = 0; i < cfg->plugin_count; i++) {
    free(cfg->plugins[i].name);
    free(cfg->plugins[i].exec);
  }
  free(cfg->plugins);

  for (size_t i = 0; i < cfg->trunk_count; i++) {
    config_trunk *t = &cfg->trunks[i];
    free(t->name);
    free(t->host);
    free(t->port);
    free(t->username);
    free(t->password);
    free(t->cid);
    free(t->cid_name);
    free(t->overflow_strategy);
    free(t->overflow_target);
    free(t->user_agent);
    free(t->group_prefix);
    for (size_t j = 0; j < t->did_count; j++)
      free(t->dids[j]);
    free(t->dids);
    if (t->rewrite_regex && t->rewrite_count > 0) {
      regex_t *re = (regex_t *)t->rewrite_regex;
      for (size_t j = 0; j < t->rewrite_count; j++)
        regfree(&re[j]);
      free(t->rewrite_regex);
      t->rewrite_regex = NULL;
    }
    for (size_t j = 0; j < t->rewrite_count; j++) {
      free(t->rewrites[j].pattern);
      free(t->rewrites[j].replace);
    }
    free(t->rewrites);
  }
  free(cfg->trunks);

  for (size_t i = 0; i < cfg->extension_count; i++) {
    free(cfg->extensions[i].number);
    free(cfg->extensions[i].name);
    free(cfg->extensions[i].secret);
  }
  free(cfg->extensions);

  config_init(cfg);
}

void config_last_parse_error(char *section_out, size_t section_size, char *key_out, size_t key_size) {
  if (section_out && section_size) {
    size_t n = strlen(last_parse_section);
    if (n >= section_size) n = section_size - 1;
    memcpy(section_out, last_parse_section, n);
    section_out[n] = '\0';
  }
  if (key_out && key_size) {
    size_t n = strlen(last_parse_key);
    if (n >= key_size) n = key_size - 1;
    memcpy(key_out, last_parse_key, n);
    key_out[n] = '\0';
  }
}

int config_load(upbx_config *cfg, const char *path) {
  last_parse_section[0] = '\0';
  last_parse_key[0] = '\0';
  int r = ini_parse(path, handler, cfg);
  if (r < 0)
    return -1; /* file error */
  if (r > 0)
    return r;  /* parse error line */
  return 0;
}

int config_compile_trunk_rewrites(upbx_config *cfg) {
  if (!cfg || !cfg->trunks) return 0;
  for (size_t i = 0; i < cfg->trunk_count; i++) {
    config_trunk *t = &cfg->trunks[i];
    if (t->rewrite_count == 0) continue;
    regex_t *re = (regex_t *)malloc(t->rewrite_count * sizeof(regex_t));
    if (!re) return -1;
    for (size_t j = 0; j < t->rewrite_count; j++) {
      if (regcomp(&re[j], t->rewrites[j].pattern, REG_EXTENDED) != 0) {
        for (size_t k = 0; k < j; k++) regfree(&re[k]);
        free(re);
        return -1;
      }
    }
    t->rewrite_regex = re;
  }
  return 0;
}
