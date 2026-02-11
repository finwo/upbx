#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>

#include "benhoyt/inih.h"
#include "rxi/log.h"
#include "config.h"
#include "RespModule/resp.h"

#define STRDUP(s) ((s) ? strdup(s) : NULL)
#define PREFIX_MATCH(sec, pre) (strncmp(sec, pre, sizeof(pre)-1) == 0 && (sec)[sizeof(pre)-1])
#define SECTION_TAIL(sec, pre) ((sec) + sizeof(pre) - 1)

#define TRIM_SECTION_SIZE 256
#define TRIM_NAME_SIZE    256
#define TRIM_VALUE_SIZE  2048
#define TRIM_BUF          512

#define CONFIG_REF_DEPTH_MAX 8
#define REPEATABLE_KEY(s) (strcmp(s, "permit") == 0 || strcmp(s, "did") == 0 || strcmp(s, "emergency") == 0)

typedef struct {
  char **sections;
  size_t n;
  size_t cap;
} sections_ctx_t;

typedef struct {
  char *key;
  int is_array;
  int is_ref;  /* value is resolved resp_object* (single key only) */
  union {
    char *single;
    struct { char **ptr; size_t n; size_t cap; } arr;
    resp_object *ref;
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

static resp_object *config_section_get_path_impl(const char *path, const char *section, unsigned depth);

/* Pair pattern with following replace in [trunk:...] */
static char *pending_rewrite_pattern;
/* Last parse error (section/key) when handler returns 0; used for error reporting. */
static char last_parse_section[TRIM_SECTION_SIZE];
static char last_parse_key[TRIM_NAME_SIZE];
/* Live config API */
static const char *stored_config_path;

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

void config_set_path(const char *path) {
  stored_config_path = path;
}

const char *config_get_path(void) {
  return stored_config_path;
}

/* Unescape: \\ -> \, \@ -> @. Caller must free result. Returns NULL on alloc failure. */
static char *config_unescape(const char *raw) {
  if (!raw) return NULL;
  size_t len = 0;
  for (const char *p = raw; *p; p++) {
    if (p[0] == '\\' && (p[1] == '\\' || p[1] == '@')) { len++; p++; }
    else len++;
  }
  char *out = (char *)malloc(len + 1);
  if (!out) return NULL;
  char *q = out;
  for (const char *p = raw; *p; p++) {
    if (p[0] == '\\' && (p[1] == '\\' || p[1] == '@')) { *q++ = p[1]; p++; }
    else *q++ = *p;
  }
  *q = '\0';
  return out;
}

/* Split reference spec into section and optional key. Last dot separates section from key. No normalization: section is used as-is for lookup. */
static void ref_spec_to_section(const char *spec, char *section_out, size_t section_size, const char **key_out) {
  *key_out = NULL;
  if (!section_out || section_size == 0) return;
  section_out[0] = '\0';
  if (!spec) return;
  const char *last_dot = strrchr(spec, '.');
  size_t section_spec_len = strlen(spec);
  if (last_dot && last_dot > spec) {
    *key_out = last_dot + 1;
    section_spec_len = (size_t)(last_dot - spec);
  }
  if (section_spec_len >= section_size) section_spec_len = section_size - 1;
  memcpy(section_out, spec, section_spec_len);
  section_out[section_spec_len] = '\0';
}

/* Resolve @spec at given depth. Returns owned resp_object or NULL (omit key, log). path and depth required. */
static resp_object *config_resolve_ref(const char *path, const char *spec, unsigned depth) {
  if (!path || !spec || depth > CONFIG_REF_DEPTH_MAX) {
    if (depth > CONFIG_REF_DEPTH_MAX)
      log_warn("config: reference depth exceeded (max %d): %.64s", CONFIG_REF_DEPTH_MAX, spec);
    return NULL;
  }
  char *unescaped_spec = config_unescape(spec);
  if (!unescaped_spec) return NULL;
  char section_buf[TRIM_SECTION_SIZE];
  const char *sub_key = NULL;
  ref_spec_to_section(unescaped_spec, section_buf, sizeof(section_buf), &sub_key);
  free(unescaped_spec);
  resp_object *sec = config_section_get_path_impl(path, section_buf, depth + 1);
  if (!sec) {
    log_warn("config: unresolved reference @%.64s (section not found)", spec);
    return NULL;
  }
  if (!sub_key) {
    return sec;
  }
  resp_object *val = resp_map_get(sec, sub_key);
  if (!val) {
    resp_free(sec);
    log_warn("config: unresolved reference @%.64s (key not found)", spec);
    return NULL;
  }
  resp_object *copy = resp_deep_copy(val);
  resp_free(sec);
  return copy;
}

/* Collect unique section names in order of first appearance. */
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

resp_object *config_sections_list_path(const char *path) {
  if (!path) return NULL;
  sections_ctx_t ctx = { NULL, 0, 0 };
  int r = ini_parse(path, sections_handler, &ctx);
  if (r != 0) {
    for (size_t i = 0; i < ctx.n; i++) free(ctx.sections[i]);
    free(ctx.sections);
    return NULL;
  }
  resp_object *o = (resp_object *)calloc(1, sizeof(resp_object));
  if (!o) {
    for (size_t i = 0; i < ctx.n; i++) free(ctx.sections[i]);
    free(ctx.sections);
    return NULL;
  }
  o->type = RESPT_ARRAY;
  o->u.arr.n = ctx.n;
  o->u.arr.elem = (resp_object *)calloc(ctx.n, sizeof(resp_object));
  if (!o->u.arr.elem && ctx.n) {
    free(o);
    for (size_t i = 0; i < ctx.n; i++) free(ctx.sections[i]);
    free(ctx.sections);
    return NULL;
  }
  for (size_t i = 0; i < ctx.n; i++) {
    o->u.arr.elem[i].type = RESPT_BULK;
    o->u.arr.elem[i].u.s = ctx.sections[i];
  }
  free(ctx.sections);
  return o;
}

/* Section map: key/value pairs; repeatable keys (permit, did, emergency) -> value = ARRAY of strings. */
static void section_get_ctx_free(section_get_ctx_t *ctx) {
  for (size_t i = 0; i < ctx->n; i++) {
    free(ctx->entries[i].key);
    if (ctx->entries[i].is_ref)
      resp_free(ctx->entries[i].val.ref);
    else if (ctx->entries[i].is_array) {
      if (ctx->entries[i].val.arr.ptr) {
        for (size_t j = 0; j < ctx->entries[i].val.arr.n; j++) free(ctx->entries[i].val.arr.ptr[j]);
        free(ctx->entries[i].val.arr.ptr);
      }
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
      ctx->entries[ctx->n].is_ref = 0;
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
  ctx->entries[ctx->n].is_ref = 0;
  ctx->entries[ctx->n].val.single = strdup(vbuf);
  if (!ctx->entries[ctx->n].key || !ctx->entries[ctx->n].val.single) return 0;
  ctx->n++;
  return 1;
}

/* Post-process raw entries: unescape, resolve @ references. path and depth for resolution. */
static int section_entries_apply_unescape_and_refs(section_get_ctx_t *ctx, const char *path, unsigned depth) {
  for (size_t i = 0; i < ctx->n; i++) {
    section_entry_t *e = &ctx->entries[i];
    if (e->is_array) {
      if (!e->val.arr.ptr)
        continue;
      for (size_t j = 0; j < e->val.arr.n; j++) {
        char *raw = e->val.arr.ptr[j];
        if (!raw) continue;
        if (raw[0] == '@') {
          resp_object *resolved = config_resolve_ref(path, raw + 1, depth);
          free(raw);
          if (!resolved) {
            e->val.arr.ptr[j] = NULL;
            continue;
          }
          if (resolved->type == RESPT_BULK || resolved->type == RESPT_SIMPLE) {
            e->val.arr.ptr[j] = resolved->u.s ? strdup(resolved->u.s) : strdup("");
            resp_free(resolved);
          } else if (resolved->type == RESPT_ARRAY) {
            size_t add = resolved->u.arr.n;
            if (add == 0) {
              free(e->val.arr.ptr[j]);
              e->val.arr.ptr[j] = NULL;
              resp_free(resolved);
            } else {
              free(e->val.arr.ptr[j]);
              size_t need = e->val.arr.n + add - 1;
              while (e->val.arr.cap < need) {
                size_t new_cap = e->val.arr.cap ? e->val.arr.cap * 2 : 4;
                char **p = (char **)realloc(e->val.arr.ptr, new_cap * sizeof(char *));
                if (!p) { resp_free(resolved); continue; }
                e->val.arr.ptr = p;
                e->val.arr.cap = new_cap;
              }
              memmove(&e->val.arr.ptr[j + add], &e->val.arr.ptr[j + 1], (e->val.arr.n - 1 - j) * sizeof(char *));
              for (size_t a = 0; a < add; a++) {
                resp_object *elem = &resolved->u.arr.elem[a];
                e->val.arr.ptr[j + a] = (elem->type == RESPT_BULK || elem->type == RESPT_SIMPLE) && elem->u.s
                  ? strdup(elem->u.s) : strdup("");
              }
              e->val.arr.n += add - 1;
              resp_free(resolved);
            }
          } else {
            resp_free(resolved);
            e->val.arr.ptr[j] = NULL;
          }
        } else {
          char *u = config_unescape(raw);
          free(raw);
          e->val.arr.ptr[j] = u ? u : strdup("");
        }
      }
      continue;
    }
    if (e->is_ref) continue;
    char *raw = e->val.single;
    if (!raw) continue;
    if (raw[0] == '@') {
      resp_object *resolved = config_resolve_ref(path, raw + 1, depth);
      free(raw);
      e->val.single = NULL;
      if (!resolved) {
        free(e->key);
        e->key = NULL;
        continue;
      }
      e->is_ref = 1;
      e->val.ref = resolved;
    } else {
      char *u = config_unescape(raw);
      free(raw);
      e->val.single = u ? u : strdup("");
    }
  }
  return 1;
}

/* Internal: get section map with reference resolution at given depth. */
static resp_object *config_section_get_path_impl(const char *path, const char *section, unsigned depth) {
  if (!path || !section) return NULL;
  section_get_ctx_t ctx = { section, NULL, 0, 0, "", 0 };
  int r = ini_parse(path, section_get_handler, &ctx);
  if (r != 0) {
    section_get_ctx_free(&ctx);
    return NULL;
  }
  section_entries_apply_unescape_and_refs(&ctx, path, depth);
  size_t valid = 0;
  for (size_t i = 0; i < ctx.n; i++)
    if (ctx.entries[i].key) valid++;
  resp_object *o = (resp_object *)calloc(1, sizeof(resp_object));
  if (!o) { section_get_ctx_free(&ctx); return NULL; }
  o->type = RESPT_ARRAY;
  o->u.arr.n = valid * 2;
  o->u.arr.elem = (resp_object *)calloc(o->u.arr.n, sizeof(resp_object));
  if (!o->u.arr.elem && valid) {
    free(o);
    section_get_ctx_free(&ctx);
    return NULL;
  }
  for (size_t i = 0, j = 0; i < ctx.n; i++) {
    if (!ctx.entries[i].key) continue;
    o->u.arr.elem[j].type = RESPT_BULK;
    o->u.arr.elem[j].u.s = ctx.entries[i].key;
    ctx.entries[i].key = NULL;
    if (ctx.entries[i].is_ref) {
      resp_object *copy = resp_deep_copy(ctx.entries[i].val.ref);
      if (!copy) {
        while (j > 0) { j -= 2; free(o->u.arr.elem[j].u.s); resp_free(&o->u.arr.elem[j+1]); }
        free(o->u.arr.elem);
        free(o);
        section_get_ctx_free(&ctx);
        return NULL;
      }
      o->u.arr.elem[j + 1] = *copy;
      free(copy);
      j += 2;
      continue;
    }
    if (ctx.entries[i].is_array) {
      size_t n = 0;
      for (size_t k = 0; k < ctx.entries[i].val.arr.n; k++)
        if (ctx.entries[i].val.arr.ptr[k]) n++;
      o->u.arr.elem[j + 1].type = RESPT_ARRAY;
      o->u.arr.elem[j + 1].u.arr.n = n;
      o->u.arr.elem[j + 1].u.arr.elem = n ? (resp_object *)calloc(n, sizeof(resp_object)) : NULL;
      if (n && !o->u.arr.elem[j + 1].u.arr.elem) {
        while (j > 0) { j -= 2; free(o->u.arr.elem[j].u.s); resp_free(&o->u.arr.elem[j+1]); }
        free(o->u.arr.elem);
        free(o);
        section_get_ctx_free(&ctx);
        return NULL;
      }
      for (size_t k = 0, kk = 0; k < ctx.entries[i].val.arr.n; k++) {
        if (!ctx.entries[i].val.arr.ptr[k]) continue;
        o->u.arr.elem[j + 1].u.arr.elem[kk].type = RESPT_BULK;
        o->u.arr.elem[j + 1].u.arr.elem[kk].u.s = ctx.entries[i].val.arr.ptr[k];
        ctx.entries[i].val.arr.ptr[k] = NULL;
        kk++;
      }
      free(ctx.entries[i].val.arr.ptr);
      ctx.entries[i].val.arr.ptr = NULL;
    } else {
      o->u.arr.elem[j + 1].type = RESPT_BULK;
      o->u.arr.elem[j + 1].u.s = ctx.entries[i].val.single;
      ctx.entries[i].val.single = NULL;
    }
    j += 2;
  }
  section_get_ctx_free(&ctx);
  return o;
}

resp_object *config_section_get_path(const char *path, const char *section) {
  return config_section_get_path_impl(path, section, 0);
}

/* Key get: return single value (string/int) or ARRAY for repeatable key. */
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

resp_object *config_key_get_path(const char *path, const char *section, const char *key) {
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
  if (ctx.is_repeatable) {
    for (size_t i = 0; i < ctx.val_count; i++) {
      char *raw = ctx.vals[i];
      char *u = config_unescape(raw);
      free(raw);
      ctx.vals[i] = u ? u : strdup("");
    }
  } else if (!ctx.want_int && ctx.single_val && ctx.single_val[0] == '@') {
    resp_object *resolved = config_resolve_ref(path, ctx.single_val + 1, 0);
    free(ctx.single_val);
    ctx.single_val = NULL;
    if (!resolved) return NULL;
    return resolved;
  } else if (!ctx.want_int && ctx.single_val) {
    char *u = config_unescape(ctx.single_val);
    free(ctx.single_val);
    ctx.single_val = u ? u : strdup("");
  }
  resp_object *o = (resp_object *)calloc(1, sizeof(resp_object));
  if (!o) {
    for (size_t i = 0; i < ctx.val_count; i++) free(ctx.vals[i]);
    free(ctx.vals);
    free(ctx.single_val);
    return NULL;
  }
  if (ctx.is_repeatable) {
    o->type = RESPT_ARRAY;
    o->u.arr.n = ctx.val_count;
    o->u.arr.elem = (resp_object *)calloc(ctx.val_count, sizeof(resp_object));
    if (!o->u.arr.elem && ctx.val_count) {
      free(o);
      for (size_t i = 0; i < ctx.val_count; i++) free(ctx.vals[i]);
      free(ctx.vals);
      return NULL;
    }
    for (size_t i = 0; i < ctx.val_count; i++) {
      o->u.arr.elem[i].type = RESPT_BULK;
      o->u.arr.elem[i].u.s = ctx.vals[i];
    }
    free(ctx.vals);
  } else if (ctx.want_int) {
    o->type = RESPT_INT;
    o->u.i = ctx.int_val;
    free(ctx.single_val);
  } else {
    o->type = RESPT_BULK;
    o->u.s = ctx.single_val;
  }
  return o;
}

resp_object *config_sections_list(void) {
  return config_sections_list_path(stored_config_path);
}

resp_object *config_section_get(const char *section) {
  return config_section_get_path(stored_config_path, section);
}

resp_object *config_key_get(const char *section, const char *key) {
  return config_key_get_path(stored_config_path, section, key);
}
