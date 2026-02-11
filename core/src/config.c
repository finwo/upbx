#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>

#include "benhoyt/inih.h"
#include "rxi/log.h"
#include "config.h"
#include "PluginModule/plugin.h"

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
  /* filter_incoming defaults to 0 (accept any matching extension) via memset */
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
    if (strcmp(key, "cross_group_calls") == 0) {
      cfg->cross_group_calls = (atoi(val) != 0) ? 1 : 0;
      return 1;
    }
    if (strcmp(key, "emergency") == 0) {
      char **n = realloc(cfg->emergency, (cfg->emergency_count + 1) * sizeof(char *));
      if (n) { cfg->emergency = n; cfg->emergency[cfg->emergency_count++] = STRDUP(val); }
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
    if (strcmp(key, "filter_incoming") == 0) {
      t->filter_incoming = (atoi(val) != 0) ? 1 : 0;
      return 1;
    }
    log_warn("config line %d: unknown key '%s' in section '%s'", lineno, key, sec);
    return 1;
  }

  if (strcmp(sec, "api") == 0) {
    if (strcmp(key, "listen") == 0) {
      free(cfg->api.listen);
      cfg->api.listen = STRDUP(val);
      return 1;
    }
    log_warn("config line %d: unknown key '%s' in section '%s'", lineno, key, sec);
    return 1;
  }

  if (PREFIX_MATCH(sec, "api:")) {
    const char *uname = SECTION_TAIL(sec, "api:");
    /* Find or create user entry */
    config_api_user *u = NULL;
    for (size_t i = 0; i < cfg->api.user_count; i++) {
      if (strcmp(cfg->api.users[i].username, uname) == 0) { u = &cfg->api.users[i]; break; }
    }
    if (!u) {
      size_t old = cfg->api.user_count++;
      cfg->api.users = (config_api_user *)realloc(cfg->api.users, cfg->api.user_count * sizeof(config_api_user));
      if (!cfg->api.users) { cfg->api.user_count = old; set_last_parse_error(sec, key); return 0; }
      u = &cfg->api.users[old];
      memset(u, 0, sizeof(*u));
      u->username = STRDUP(uname);
      if (!u->username) { cfg->api.user_count = old; set_last_parse_error(sec, key); return 0; }
    }
    if (strcmp(key, "secret") == 0) {
      free(u->secret);
      u->secret = STRDUP(val);
      return 1;
    }
    if (strcmp(key, "permit") == 0) {
      char **p = (char **)realloc(u->permits, (u->permit_count + 1) * sizeof(char *));
      if (!p) { set_last_parse_error(sec, key); return 0; }
      u->permits = p;
      u->permits[u->permit_count] = STRDUP(val);
      if (!u->permits[u->permit_count]) { set_last_parse_error(sec, key); return 0; }
      u->permit_count++;
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
  cfg->cross_group_calls = 1;
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

  free(cfg->api.listen);
  for (size_t i = 0; i < cfg->api.user_count; i++) {
    config_api_user *u = &cfg->api.users[i];
    free(u->username);
    free(u->secret);
    for (size_t j = 0; j < u->permit_count; j++)
      free(u->permits[j]);
    free(u->permits);
  }
  free(cfg->api.users);

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
  log_trace("config_load: path=%s", path ? path : "(null)");
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
  log_trace("config_compile_trunk_rewrites: %zu trunk(s)", cfg ? cfg->trunk_count : 0);
  if (!cfg || !cfg->trunks) return 0;
  for (size_t i = 0; i < cfg->trunk_count; i++) {
    config_trunk *t = &cfg->trunks[i];
    if (t->rewrite_count == 0) continue;
    regex_t *re = (regex_t *)malloc(t->rewrite_count * sizeof(regex_t));
    if (!re) return -1;
    for (size_t j = 0; j < t->rewrite_count; j++) {
      if (regcomp(&re[j], t->rewrites[j].pattern, REG_EXTENDED) != 0) {
        log_error("trunk %s: regex compile failed for pattern \"%s\"", t->name, t->rewrites[j].pattern);
        for (size_t k = 0; k < j; k++) regfree(&re[k]);
        free(re);
        return -1;
      }
    }
    t->rewrite_regex = re;
  }
  return 0;
}

/* --- Live config API --- */
static const char *stored_config_path;

void config_set_path(const char *path) {
  stored_config_path = path;
}

const char *config_get_path(void) {
  return stored_config_path;
}

#define TRIM_BUF 512

/* Collect unique section names in order of first appearance. */
typedef struct {
  char **sections;
  size_t n;
  size_t cap;
} sections_ctx_t;

static int sections_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  (void)name;
  (void)value;
  (void)lineno;
  sections_ctx_t *ctx = (sections_ctx_t *)user;
  if (!section || !section[0]) return 1;
  for (size_t i = 0; i < ctx->n; i++)
    if (strcmp(ctx->sections[i], section) == 0)
      return 1;
  if (ctx->n >= ctx->cap) {
    size_t new_cap = ctx->cap ? ctx->cap * 2 : 8;
    char **p = (char **)realloc(ctx->sections, new_cap * sizeof(char *));
    if (!p) return 0;
    ctx->sections = p;
    ctx->cap = new_cap;
  }
  ctx->sections[ctx->n] = strdup(section);
  if (!ctx->sections[ctx->n]) return 0;
  ctx->n++;
  return 1;
}

plugmod_resp_object *config_sections_list_path(const char *path) {
  if (!path) return NULL;
  sections_ctx_t ctx = { NULL, 0, 0 };
  int r = ini_parse(path, sections_handler, &ctx);
  if (r != 0) {
    for (size_t i = 0; i < ctx.n; i++) free(ctx.sections[i]);
    free(ctx.sections);
    return NULL;
  }
  plugmod_resp_object *o = (plugmod_resp_object *)calloc(1, sizeof(plugmod_resp_object));
  if (!o) {
    for (size_t i = 0; i < ctx.n; i++) free(ctx.sections[i]);
    free(ctx.sections);
    return NULL;
  }
  o->type = PLUGMOD_RESPT_ARRAY;
  o->u.arr.n = ctx.n;
  o->u.arr.elem = (plugmod_resp_object *)calloc(ctx.n, sizeof(plugmod_resp_object));
  if (!o->u.arr.elem && ctx.n) {
    free(o);
    for (size_t i = 0; i < ctx.n; i++) free(ctx.sections[i]);
    free(ctx.sections);
    return NULL;
  }
  for (size_t i = 0; i < ctx.n; i++) {
    o->u.arr.elem[i].type = PLUGMOD_RESPT_BULK;
    o->u.arr.elem[i].u.s = ctx.sections[i];
  }
  free(ctx.sections);
  return o;
}

/* Section map: key/value pairs; repeatable keys (permit, did, emergency) → value = ARRAY of strings. */
#define REPEATABLE_KEY(s) (strcmp(s, "permit") == 0 || strcmp(s, "did") == 0 || strcmp(s, "emergency") == 0)
typedef struct {
  char *key;
  int is_array;
  union {
    char *single;
    struct { char **ptr; size_t n; size_t cap; } arr;
  } val;
} section_entry_t;

typedef struct {
  const char *target_section;
  section_entry_t *entries;
  size_t n;
  size_t cap;
  char current_repeatable_key[TRIM_BUF];
  size_t repeatable_val_cap;
} section_get_ctx_t;

static void section_get_ctx_free(section_get_ctx_t *ctx) {
  for (size_t i = 0; i < ctx->n; i++) {
    free(ctx->entries[i].key);
    if (ctx->entries[i].is_array) {
      for (size_t j = 0; j < ctx->entries[i].val.arr.n; j++) free(ctx->entries[i].val.arr.ptr[j]);
      free(ctx->entries[i].val.arr.ptr);
    } else {
      free(ctx->entries[i].val.single);
    }
  }
  free(ctx->entries);
}

static int section_get_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  (void)lineno;
  section_get_ctx_t *ctx = (section_get_ctx_t *)user;
  if (!section || strcmp(section, ctx->target_section) != 0) return 1;
  if (!name || !name[0]) return 1;
  char kbuf[TRIM_BUF], vbuf[TRIM_VALUE_SIZE];
  trim_copy(kbuf, sizeof(kbuf), name);
  trim_copy(vbuf, sizeof(vbuf), value ? value : "");
  if (REPEATABLE_KEY(kbuf)) {
    if (strcmp(ctx->current_repeatable_key, kbuf) != 0) {
      ctx->current_repeatable_key[0] = '\0';
      for (size_t i = 0; i < ctx->n; i++)
        if (ctx->entries[i].is_array && strcmp(ctx->entries[i].key, kbuf) == 0) {
          if (ctx->entries[i].val.arr.n >= ctx->entries[i].val.arr.cap) {
            size_t new_cap = ctx->entries[i].val.arr.cap ? ctx->entries[i].val.arr.cap * 2 : 4;
            char **p = (char **)realloc(ctx->entries[i].val.arr.ptr, new_cap * sizeof(char *));
            if (!p) return 0;
            ctx->entries[i].val.arr.ptr = p;
            ctx->entries[i].val.arr.cap = new_cap;
          }
          ctx->entries[i].val.arr.ptr[ctx->entries[i].val.arr.n++] = strdup(vbuf);
          strncpy(ctx->current_repeatable_key, kbuf, sizeof(ctx->current_repeatable_key) - 1);
          ctx->current_repeatable_key[sizeof(ctx->current_repeatable_key) - 1] = '\0';
          return 1;
        }
      if (ctx->n >= ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2 : 8;
        section_entry_t *p = (section_entry_t *)realloc(ctx->entries, new_cap * sizeof(section_entry_t));
        if (!p) return 0;
        ctx->entries = p;
        ctx->cap = new_cap;
      }
      ctx->entries[ctx->n].key = strdup(kbuf);
      ctx->entries[ctx->n].is_array = 1;
      ctx->entries[ctx->n].val.arr.ptr = (char **)malloc(4 * sizeof(char *));
      ctx->entries[ctx->n].val.arr.cap = 4;
      ctx->entries[ctx->n].val.arr.n = 0;
      if (!ctx->entries[ctx->n].key || !ctx->entries[ctx->n].val.arr.ptr) return 0;
      ctx->entries[ctx->n].val.arr.ptr[ctx->entries[ctx->n].val.arr.n++] = strdup(vbuf);
      strncpy(ctx->current_repeatable_key, kbuf, sizeof(ctx->current_repeatable_key) - 1);
      ctx->n++;
    } else {
      for (size_t i = 0; i < ctx->n; i++)
        if (ctx->entries[i].is_array && strcmp(ctx->entries[i].key, kbuf) == 0) {
          if (ctx->entries[i].val.arr.n >= ctx->entries[i].val.arr.cap) {
            size_t new_cap = ctx->entries[i].val.arr.cap * 2;
            char **p = (char **)realloc(ctx->entries[i].val.arr.ptr, new_cap * sizeof(char *));
            if (!p) return 0;
            ctx->entries[i].val.arr.ptr = p;
            ctx->entries[i].val.arr.cap = new_cap;
          }
          ctx->entries[i].val.arr.ptr[ctx->entries[i].val.arr.n++] = strdup(vbuf);
          break;
        }
    }
    return 1;
  }
  if (ctx->n >= ctx->cap) {
    size_t new_cap = ctx->cap ? ctx->cap * 2 : 8;
    section_entry_t *p = (section_entry_t *)realloc(ctx->entries, new_cap * sizeof(section_entry_t));
    if (!p) return 0;
    ctx->entries = p;
    ctx->cap = new_cap;
  }
  ctx->current_repeatable_key[0] = '\0';
  ctx->entries[ctx->n].key = strdup(kbuf);
  ctx->entries[ctx->n].is_array = 0;
  ctx->entries[ctx->n].val.single = strdup(vbuf);
  if (!ctx->entries[ctx->n].key || !ctx->entries[ctx->n].val.single) return 0;
  ctx->n++;
  return 1;
}

plugmod_resp_object *config_section_get_path(const char *path, const char *section) {
  if (!path || !section) return NULL;
  section_get_ctx_t ctx = { section, NULL, 0, 0, "", 0 };
  int r = ini_parse(path, section_get_handler, &ctx);
  if (r != 0) {
    section_get_ctx_free(&ctx);
    return NULL;
  }
  plugmod_resp_object *o = (plugmod_resp_object *)calloc(1, sizeof(plugmod_resp_object));
  if (!o) { section_get_ctx_free(&ctx); return NULL; }
  o->type = PLUGMOD_RESPT_ARRAY;
  o->u.arr.n = ctx.n * 2;
  o->u.arr.elem = (plugmod_resp_object *)calloc(o->u.arr.n, sizeof(plugmod_resp_object));
  if (!o->u.arr.elem) {
    free(o);
    section_get_ctx_free(&ctx);
    return NULL;
  }
  for (size_t i = 0, j = 0; i < ctx.n; i++, j += 2) {
    o->u.arr.elem[j].type = PLUGMOD_RESPT_BULK;
    o->u.arr.elem[j].u.s = strdup(ctx.entries[i].key);
    if (ctx.entries[i].is_array) {
      o->u.arr.elem[j + 1].type = PLUGMOD_RESPT_ARRAY;
      o->u.arr.elem[j + 1].u.arr.n = ctx.entries[i].val.arr.n;
      o->u.arr.elem[j + 1].u.arr.elem = (plugmod_resp_object *)calloc(ctx.entries[i].val.arr.n, sizeof(plugmod_resp_object));
      if (!o->u.arr.elem[j + 1].u.arr.elem) {
        while (j > 0) { j -= 2; free(o->u.arr.elem[j].u.s); if (o->u.arr.elem[j+1].type == PLUGMOD_RESPT_ARRAY) { for (size_t k = 0; k < o->u.arr.elem[j+1].u.arr.n; k++) free(o->u.arr.elem[j+1].u.arr.elem[k].u.s); free(o->u.arr.elem[j+1].u.arr.elem); } }
        free(o->u.arr.elem);
        free(o);
        section_get_ctx_free(&ctx);
        return NULL;
      }
      for (size_t k = 0; k < ctx.entries[i].val.arr.n; k++) {
        o->u.arr.elem[j + 1].u.arr.elem[k].type = PLUGMOD_RESPT_BULK;
        o->u.arr.elem[j + 1].u.arr.elem[k].u.s = ctx.entries[i].val.arr.ptr[k];
      }
      free(ctx.entries[i].val.arr.ptr);
      ctx.entries[i].val.arr.ptr = NULL;
    } else {
      o->u.arr.elem[j + 1].type = PLUGMOD_RESPT_BULK;
      o->u.arr.elem[j + 1].u.s = ctx.entries[i].val.single;
    }
    free(ctx.entries[i].key);
    ctx.entries[i].key = NULL;
  }
  free(ctx.entries);
  return o;
}

/* Key get: return single value (string/int) or ARRAY for repeatable key. */
typedef struct {
  const char *target_section;
  const char *target_key;
  int found;
  int is_repeatable;
  char **vals;
  size_t val_count;
  size_t val_cap;
  char *single_val;
  long long int_val;
  int want_int;
} key_get_ctx_t;

static int key_get_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  (void)lineno;
  key_get_ctx_t *ctx = (key_get_ctx_t *)user;
  if (!section || strcmp(section, ctx->target_section) != 0) return 1;
  if (!name || strcmp(name, ctx->target_key) != 0) return 1;
  char vbuf[TRIM_VALUE_SIZE];
  trim_copy(vbuf, sizeof(vbuf), value ? value : "");
  if (REPEATABLE_KEY(ctx->target_key)) {
    ctx->found = 1;
    if (ctx->val_count >= ctx->val_cap) {
      size_t new_cap = ctx->val_cap ? ctx->val_cap * 2 : 4;
      char **p = (char **)realloc(ctx->vals, new_cap * sizeof(char *));
      if (!p) return 0;
      ctx->vals = p;
      ctx->val_cap = new_cap;
    }
    ctx->vals[ctx->val_count++] = strdup(vbuf);
    return 1;
  }
  ctx->found = 1;
  if (ctx->want_int) {
    ctx->int_val = (long long)atoll(vbuf);
  } else {
    free(ctx->single_val);
    ctx->single_val = strdup(vbuf);
  }
  return 1;
}

plugmod_resp_object *config_key_get_path(const char *path, const char *section, const char *key) {
  if (!path || !section || !key) return NULL;
  key_get_ctx_t ctx = {
    .target_section = section,
    .target_key = key,
    .found = 0,
    .is_repeatable = REPEATABLE_KEY(key),
    .vals = NULL,
    .val_count = 0,
    .val_cap = 0,
    .single_val = NULL,
    .int_val = 0,
    .want_int = (strcmp(key, "locality") == 0 || strcmp(key, "daemonize") == 0 || strcmp(key, "rtp_port_low") == 0 || strcmp(key, "rtp_port_high") == 0 || strcmp(key, "cross_group_calls") == 0 || strcmp(key, "overflow_timeout") == 0 || strcmp(key, "filter_incoming") == 0)
  };
  int r = ini_parse(path, key_get_handler, &ctx);
  if (r != 0 || !ctx.found) {
    for (size_t i = 0; i < ctx.val_count; i++) free(ctx.vals[i]);
    free(ctx.vals);
    free(ctx.single_val);
    return NULL;
  }
  plugmod_resp_object *o = (plugmod_resp_object *)calloc(1, sizeof(plugmod_resp_object));
  if (!o) {
    for (size_t i = 0; i < ctx.val_count; i++) free(ctx.vals[i]);
    free(ctx.vals);
    free(ctx.single_val);
    return NULL;
  }
  if (ctx.is_repeatable) {
    o->type = PLUGMOD_RESPT_ARRAY;
    o->u.arr.n = ctx.val_count;
    o->u.arr.elem = (plugmod_resp_object *)calloc(ctx.val_count, sizeof(plugmod_resp_object));
    if (!o->u.arr.elem && ctx.val_count) {
      free(o);
      for (size_t i = 0; i < ctx.val_count; i++) free(ctx.vals[i]);
      free(ctx.vals);
      return NULL;
    }
    for (size_t i = 0; i < ctx.val_count; i++) {
      o->u.arr.elem[i].type = PLUGMOD_RESPT_BULK;
      o->u.arr.elem[i].u.s = ctx.vals[i];
    }
    free(ctx.vals);
  } else if (ctx.want_int) {
    o->type = PLUGMOD_RESPT_INT;
    o->u.i = ctx.int_val;
    free(ctx.single_val);
  } else {
    o->type = PLUGMOD_RESPT_BULK;
    o->u.s = ctx.single_val;
  }
  return o;
}

plugmod_resp_object *config_sections_list(void) {
  return config_sections_list_path(stored_config_path);
}

plugmod_resp_object *config_section_get(const char *section) {
  return config_section_get_path(stored_config_path, section);
}

plugmod_resp_object *config_key_get(const char *section, const char *key) {
  return config_key_get_path(stored_config_path, section, key);
}
