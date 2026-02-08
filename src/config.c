#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>

#include "benhoyt/inih.h"
#include "config.h"

#define STRDUP(s) ((s) ? strdup(s) : NULL)

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

static int handler(void *user, const char *section, const char *name, const char *value) {
  upbx_config *cfg = (upbx_config *)user;

  if (strcmp(section, "upbx") == 0) {
    if (strcmp(name, "locality") == 0) {
      cfg->locality = atoi(value);
      return 1;
    }
    if (strcmp(name, "daemonize") == 0) {
      cfg->daemonize = (atoi(value) != 0) ? 1 : 0;
      return 1;
    }
    if (strcmp(name, "listen") == 0) {
      free(cfg->listen);
      cfg->listen = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "rtp_ports") == 0) {
      int low = 0, high = 0;
      if (sscanf(value, "%d-%d", &low, &high) == 2 && low > 0 && high >= low) {
        cfg->rtp_port_low = low;
        cfg->rtp_port_high = high;
      }
      return 1;
    }
    if (strcmp(name, "emergency") == 0) {
      char **p = (char **)realloc(cfg->emergency, (cfg->emergency_count + 1) * sizeof(char *));
      if (!p) return 0;
      cfg->emergency = p;
      cfg->emergency[cfg->emergency_count] = STRDUP(value);
      if (!cfg->emergency[cfg->emergency_count]) return 0;
      cfg->emergency_count++;
      return 1;
    }
    return 0;
  }

  if (PREFIX_MATCH(section, "plugin:")) {
    config_plugin *p = find_or_add_plugin(cfg, SECTION_TAIL(section, "plugin:"));
    if (!p) return 0;
    if (strcmp(name, "exec") == 0) {
      free(p->exec);
      p->exec = STRDUP(value);
      return 1;
    }
    return 0;
  }

  if (PREFIX_MATCH(section, "trunk:")) {
    config_trunk *t = find_or_add_trunk(cfg, SECTION_TAIL(section, "trunk:"));
    if (!t) return 0;
    if (strcmp(name, "host") == 0) {
      free(t->host);
      t->host = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "port") == 0) {
      free(t->port);
      t->port = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "username") == 0) {
      free(t->username);
      t->username = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "password") == 0) {
      free(t->password);
      t->password = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "did") == 0)
      return append_trunk_did(t, value) ? 1 : 0;
    if (strcmp(name, "cid") == 0) {
      free(t->cid);
      t->cid = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "cid_name") == 0) {
      free(t->cid_name);
      t->cid_name = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "pattern") == 0) {
      free(pending_rewrite_pattern);
      pending_rewrite_pattern = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "replace") == 0) {
      if (pending_rewrite_pattern) {
        int ok = append_trunk_rewrite(t, pending_rewrite_pattern, value);
        free(pending_rewrite_pattern);
        pending_rewrite_pattern = NULL;
        return ok ? 1 : 0;
      }
      return 0; /* replace without preceding pattern */
    }
    if (strcmp(name, "overflow_timeout") == 0) {
      t->overflow_timeout = atoi(value);
      return 1;
    }
    if (strcmp(name, "overflow_strategy") == 0) {
      free(t->overflow_strategy);
      t->overflow_strategy = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "overflow_target") == 0) {
      free(t->overflow_target);
      t->overflow_target = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "user_agent") == 0) {
      free(t->user_agent);
      t->user_agent = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "group") == 0) {
      free(t->group_prefix);
      t->group_prefix = STRDUP(value);
      return 1;
    }
    return 0;
  }

  if (PREFIX_MATCH(section, "ext:")) {
    config_extension *e = find_or_add_extension(cfg, SECTION_TAIL(section, "ext:"));
    if (!e) return 0;
    if (strcmp(name, "name") == 0) {
      free(e->name);
      e->name = STRDUP(value);
      return 1;
    }
    if (strcmp(name, "secret") == 0) {
      free(e->secret);
      e->secret = STRDUP(value);
      return 1;
    }
    return 0;
  }

  return 0; /* unknown section */
}

void config_init(upbx_config *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->rtp_port_low = 10000;
  cfg->rtp_port_high = 20000;
}

void config_free(upbx_config *cfg) {
  free(cfg->listen);
  for (size_t i = 0; i < cfg->emergency_count; i++)
    free(cfg->emergency[i]);
  free(cfg->emergency);

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

int config_load(upbx_config *cfg, const char *path) {
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
