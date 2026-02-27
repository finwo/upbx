#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>

#include "benhoyt/inih.h"
#include "rxi/log.h"
#include "config.h"
#include "RespModule/resp.h"

resp_object *global_cfg = NULL;
resp_object *pending_cfg = NULL;

static resp_object *cfg_active_data = NULL;
static resp_object *cfg_pending_data = NULL;
static volatile int config_reload_pending = 0;
static const char *stored_config_path;

#define TRIM_SECTION_SIZE 256
#define TRIM_NAME_SIZE    256
#define TRIM_VALUE_SIZE  2048

static char last_parse_section[TRIM_SECTION_SIZE];
static char last_parse_key[TRIM_NAME_SIZE];

#define MAX_TRUNK_REWRITES 64
typedef struct {
  char *trunk_name;
  regex_t re;
  char *replace;
} trunk_rewrite_t;
static trunk_rewrite_t trunk_rewrites[MAX_TRUNK_REWRITES];
static size_t n_trunk_rewrites = 0;

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

static int is_int_key(const char *section, const char *key) {
  static const char *upbx_int_keys[] = {
    "locality", "daemonize", "tcp_keepalive_interval", "sip_tcp_port", "sip_udp_port",
    "rtp_port_low", "rtp_port_high", "api_port", NULL
  };
  static const char *trunk_int_keys[] = {
    "port", "overflow_timeout", "expires", "retry_interval", NULL
  };
  static const char *ext_int_keys[] = {
    "expires", NULL
  };
  static const char *plugin_int_keys[] = {
    "timeout", NULL
  };

  const char **keys = NULL;
  if (strncmp(section, "upbx", 4) == 0) keys = upbx_int_keys;
  else if (strncmp(section, "trunk:", 6) == 0) keys = trunk_int_keys;
  else if (strncmp(section, "ext:", 4) == 0) keys = ext_int_keys;
  else if (strncmp(section, "plugin:", 7) == 0) keys = plugin_int_keys;

  if (!keys) return 0;
  for (int i = 0; keys[i]; i++) {
    if (strcmp(key, keys[i]) == 0) return 1;
  }
  return 0;
}

static int config_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  (void)lineno;
  resp_object *cfg = (resp_object *)user;
  char sec[TRIM_SECTION_SIZE], key[TRIM_NAME_SIZE], val[TRIM_VALUE_SIZE];
  trim_copy(sec, sizeof(sec), section);
  trim_copy(key, sizeof(key), name);
  trim_copy(val, sizeof(val), value);

  resp_object *sec_obj = resp_map_get(cfg, sec);
  if (!sec_obj || sec_obj->type != RESPT_ARRAY) {
    sec_obj = resp_array_init();
    resp_map_set(cfg, sec, sec_obj);
    sec_obj = resp_map_get(cfg, sec);
  }

  if (sec_obj && sec_obj->type == RESPT_ARRAY) {
    resp_array_append_bulk(sec_obj, key);
    if (is_int_key(sec, key)) {
      long num = strtol(val, NULL, 10);
      resp_array_append_int(sec_obj, num);
    } else {
      resp_array_append_bulk(sec_obj, val);
    }
  } else {
    resp_map_set(cfg, sec, resp_array_init());
  }

  return 1;
}

void config_init(void) {
  if (cfg_active_data) {
    resp_free(cfg_active_data);
  }
  cfg_active_data = resp_array_init();
  global_cfg = cfg_active_data;

  resp_object *upbx = resp_array_init();
  resp_array_append_bulk(upbx, "locality");
  resp_array_append_bulk(upbx, "0");
  resp_array_append_bulk(upbx, "daemonize");
  resp_array_append_bulk(upbx, "0");
  resp_array_append_bulk(upbx, "cross_group_calls");
  resp_array_append_bulk(upbx, "1");
  resp_map_set(global_cfg, "upbx", upbx);

  resp_object *rtpproxy = resp_array_init();
  resp_array_append_bulk(rtpproxy, "mode");
  resp_array_append_bulk(rtpproxy, "builtin");
  resp_array_append_bulk(rtpproxy, "socket");
  resp_array_append_bulk(rtpproxy, "/var/run/rtpproxy.sock");
  resp_array_append_bulk(rtpproxy, "port_low");
  resp_array_append_simple(rtpproxy, "10000");
  resp_array_append_bulk(rtpproxy, "port_high");
  resp_array_append_simple(rtpproxy, "20000");
  resp_map_set(global_cfg, "rtpproxy", rtpproxy);
}

void config_pending_init(void) {
  if (cfg_pending_data) {
    resp_free(cfg_pending_data);
  }
  cfg_pending_data = resp_array_init();
  pending_cfg = cfg_pending_data;
}

void config_swap(void) {
  resp_object *old = global_cfg;
  global_cfg = pending_cfg;
  pending_cfg = old;

  cfg_active_data = global_cfg;
  cfg_pending_data = pending_cfg;
  config_reload_pending = 0;
}

void config_trigger_reload(void) {
  config_reload_pending = 1;
}

int config_is_reload_pending(void) {
  return config_reload_pending;
}

int config_reload(void) {
  const char *path = config_get_path();
  if (!path) {
    log_error("config_reload: no config path set");
    return -1;
  }

  config_pending_init();
  int r = config_load(pending_cfg, path);
  if (r < 0) {
    log_error("config_reload: cannot open config: %s", path);
    return -1;
  }
  if (r > 0) {
    char err_sec[256], err_key[256];
    config_last_parse_error(err_sec, sizeof(err_sec), err_key, sizeof(err_key));
    log_error("config reload parse error at line %d: unknown key '%s' in section '%s'", r, err_key[0] ? err_key : "(none)", err_sec[0] ? err_sec : "(none)");
    return r;
  }
  r = config_compile_trunk_rewrites(pending_cfg);
  if (r != 0) {
    log_error("config_reload: trunk rewrite compile failed");
    return -1;
  }

  config_swap();
  log_info("config reloaded from %s", path);
  return 0;
}

void config_lock(void) {
}

void config_unlock(void) {
}

void config_free(resp_object *cfg) {
  if (cfg) {
    resp_free(cfg);
  }
}

int config_load(resp_object *cfg, const char *path) {
  log_trace("config_load: path=%s", path ? path : "(null)");
  last_parse_section[0] = '\0';
  last_parse_key[0] = '\0';
  int r = ini_parse(path, config_handler, cfg);
  if (r < 0)
    return -1;
  if (r > 0)
    return r;
  return 0;
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

int config_compile_trunk_rewrites(resp_object *cfg) {
  log_trace("config_compile_trunk_rewrites");

  for (size_t i = 0; i < n_trunk_rewrites; i++) {
    if (trunk_rewrites[i].trunk_name) free(trunk_rewrites[i].trunk_name);
    if (trunk_rewrites[i].replace) free(trunk_rewrites[i].replace);
    regfree(&trunk_rewrites[i].re);
  }
  n_trunk_rewrites = 0;

  for (size_t i = 0; i < 256; i++) {
    char key[32];
    snprintf(key, sizeof(key), "trunk:%zu", i);
    resp_object *trunk = resp_map_get(cfg, key);
    if (!trunk || trunk->type != RESPT_ARRAY) continue;

    const char *trunk_name = NULL;
    const char *pattern = NULL;
    const char *replace = NULL;

    for (size_t j = 0; j + 1 < trunk->u.arr.n; j += 2) {
      if (trunk->u.arr.elem[j].type != RESPT_BULK) continue;
      const char *k = trunk->u.arr.elem[j].u.s;
      if (!k) continue;
      if (strcmp(k, "name") == 0 && trunk->u.arr.elem[j+1].type == RESPT_BULK) {
        trunk_name = trunk->u.arr.elem[j+1].u.s;
      } else if (strcmp(k, "pattern") == 0 && trunk->u.arr.elem[j+1].type == RESPT_BULK) {
        pattern = trunk->u.arr.elem[j+1].u.s;
      } else if (strcmp(k, "replace") == 0 && trunk->u.arr.elem[j+1].type == RESPT_BULK) {
        replace = trunk->u.arr.elem[j+1].u.s;
      }
    }

    if (trunk_name && pattern && replace && n_trunk_rewrites < MAX_TRUNK_REWRITES) {
      int r = regcomp(&trunk_rewrites[n_trunk_rewrites].re, pattern, REG_ICASE|REG_EXTENDED);
      if (r != 0) {
        char errbuf[256];
        regerror(r, &trunk_rewrites[n_trunk_rewrites].re, errbuf, sizeof(errbuf));
        log_error("trunk '%s': invalid pattern '%s': %s", trunk_name, pattern, errbuf);
        continue;
      }
      trunk_rewrites[n_trunk_rewrites].trunk_name = strdup(trunk_name);
      trunk_rewrites[n_trunk_rewrites].replace = strdup(replace);
      n_trunk_rewrites++;
      log_info("trunk '%s': rewrite pattern '%s' -> '%s'", trunk_name, pattern, replace);
    }
  }

  log_info("compiled %zu trunk rewrite rules", n_trunk_rewrites);
  return 0;
}

int config_rewrite_destination(const char *trunk_name, const char *input, char *output, size_t out_size) {
  if (!input || !output || out_size == 0) return -1;
  output[0] = '\0';

  for (size_t i = 0; i < n_trunk_rewrites; i++) {
    if (trunk_name && strcmp(trunk_rewrites[i].trunk_name, trunk_name) != 0) continue;

    regmatch_t pmatch[10];
    if (regexec(&trunk_rewrites[i].re, input, 10, pmatch, 0) != 0) continue;

    char buf[256];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *rp = strdup(trunk_rewrites[i].replace);
    if (!rp) break;

    for (char *pos = rp; *pos; pos++) {
      if (*pos == '\\' && *(pos + 1) > '0' && *(pos + 1) <= '9') {
        int idx = *(pos + 1) - '0';
        int so = pmatch[idx].rm_so;
        int n = pmatch[idx].rm_eo - so;
        if (so >= 0 && strlen(rp) + n - 1 < (int)sizeof(buf)) {
          memmove(pos + n, pos + 2, strlen(pos) - 1);
          memmove(pos, buf + so, n);
          pos = pos + n - 2;
        }
      }
    }

    int sub = pmatch[1].rm_so;
    char *p = buf;
    while (!regexec(&trunk_rewrites[i].re, p, 1, pmatch, 0)) {
      int n = pmatch[0].rm_eo - pmatch[0].rm_so;
      p += pmatch[0].rm_so;
      if (strlen(buf) - n + strlen(rp) >= (int)out_size) break;
      memmove(p + strlen(rp), p + n, strlen(p) - n + 1);
      memmove(p, rp, strlen(rp));
      p += strlen(rp);
      if (sub >= 0) break;
    }

    strncpy(output, buf, out_size - 1);
    output[out_size - 1] = '\0';
    free(rp);
    return 1;
  }

  strncpy(output, input, out_size - 1);
  output[out_size - 1] = '\0';
  return 0;
}

void config_set_path(const char *path) {
  free((void*)stored_config_path);
  stored_config_path = path ? strdup(path) : NULL;
}

const char *config_get_path(void) {
  return stored_config_path;
}

static resp_object *config_get_section_key(const char *section, const char *key) {
  if (!global_cfg) return NULL;
  resp_object *sec = resp_map_get(global_cfg, section);
  if (!sec || sec->type != RESPT_ARRAY) {
    return NULL;
  }
  resp_object *result = NULL;
  for (size_t i = 0; i + 1 < sec->u.arr.n; i += 2) {
    if (sec->u.arr.elem[i].type == RESPT_BULK &&
        sec->u.arr.elem[i].u.s &&
        strcmp(sec->u.arr.elem[i].u.s, key) == 0) {
      result = resp_deep_copy(&sec->u.arr.elem[i + 1]);
      break;
    }
  }
  return result;
}

static char *config_get_string(const char *section, const char *key) {
  resp_object *val = config_get_section_key(section, key);
  if (!val) return NULL;
  char *result = NULL;
  if (val->type == RESPT_BULK || val->type == RESPT_SIMPLE) {
    result = strdup(val->u.s ? val->u.s : "");
  }
  resp_free(val);
  return result;
}

static int config_get_int(const char *section, const char *key, int default_val) {
  resp_object *val = config_get_section_key(section, key);
  if (!val) return default_val;
  int result = default_val;
  if (val->type == RESPT_INT) {
    result = (int)val->u.i;
  } else if (val->type == RESPT_BULK || val->type == RESPT_SIMPLE) {
    result = atoi(val->u.s ? val->u.s : "");
  }
  resp_free(val);
  return result;
}

char *config_get_listen(void) {
  return config_get_string("upbx", "listen");
}

char *config_get_rtp_mode(void) {
  return config_get_string("rtpproxy", "mode");
}

char *config_get_rtp_socket(void) {
  char *s = config_get_string("rtpproxy", "socket");
  if (s && s[0]) return s;
  free(s);
  return strdup("/var/run/rtpproxy.sock");
}

char *config_get_rtp_advertise_addr(void) {
  return config_get_string("rtpproxy", "advertise_addr");
}

int config_get_rtp_port_low(void) {
  return config_get_int("rtpproxy", "port_low", 10000);
}

int config_get_rtp_port_high(void) {
  return config_get_int("rtpproxy", "port_high", 20000);
}

int config_get_locality(void) {
  return config_get_int("upbx", "locality", 0);
}

int config_get_daemonize(void) {
  return config_get_int("upbx", "daemonize", 0);
}

int config_get_cross_group_calls(void) {
  return config_get_int("upbx", "cross_group_calls", 1);
}

resp_object *config_get_extensions(void) {
  if (!global_cfg) return NULL;
  resp_object *result = resp_array_init();
  for (size_t i = 0; i < 256; i++) {
    char key[32];
    snprintf(key, sizeof(key), "ext:%zu", i);
    resp_object *ext = resp_map_get(global_cfg, key);
    if (ext && ext->type == RESPT_ARRAY) {
      resp_object *copy = resp_deep_copy(ext);
      if (copy) resp_array_append_obj(result, copy);
    }
  }
  return result;
}

resp_object *config_get_trunks(void) {
  if (!global_cfg) return NULL;
  resp_object *result = resp_array_init();
  for (size_t i = 0; i < 256; i++) {
    char key[32];
    snprintf(key, sizeof(key), "trunk:%zu", i);
    resp_object *trunk = resp_map_get(global_cfg, key);
    if (trunk && trunk->type == RESPT_ARRAY) {
      resp_object *copy = resp_deep_copy(trunk);
      if (copy) resp_array_append_obj(result, copy);
    }
  }
  return result;
}

resp_object *config_get_plugins(void) {
  if (!global_cfg) return NULL;
  resp_object *result = resp_array_init();
  for (size_t i = 0; i < 256; i++) {
    char key[32];
    snprintf(key, sizeof(key), "plugin:%zu", i);
    resp_object *plugin = resp_map_get(global_cfg, key);
    if (plugin && plugin->type == RESPT_ARRAY) {
      resp_object *copy = resp_deep_copy(plugin);
      if (copy) resp_array_append_obj(result, copy);
    }
  }
  return result;
}

resp_object *config_get_emergency(void) {
  return config_get_section_key("upbx", "emergency");
}

resp_object *config_sections_list_path(const char *path) {
  if (!path) return NULL;
  resp_object *result = resp_array_init();
  FILE *f = fopen(path, "r");
  if (!f) return result;
  char line[1024];
  char last_section[256] = "";
  while (fgets(line, sizeof(line), f)) {
    if (line[0] == '[') {
      char *end = strchr(line, ']');
      if (end) {
        *end = '\0';
        size_t len = strlen(line + 1);
        if (len >= sizeof(last_section)) len = sizeof(last_section) - 1;
        memcpy(last_section, line + 1, len);
        last_section[len] = '\0';
        int found = 0;
        for (size_t i = 0; i < result->u.arr.n; i++) {
          if (result->u.arr.elem[i].type == RESPT_BULK &&
              strcmp(result->u.arr.elem[i].u.s, last_section) == 0) {
            found = 1;
            break;
          }
        }
        if (!found) {
          resp_array_append_bulk(result, last_section);
        }
      }
    }
  }
  fclose(f);
  return result;
}

resp_object *config_section_get_path(const char *path, const char *section) {
  if (!path || !section) return NULL;
  resp_object *cfg = resp_array_init();
  int r = config_load(cfg, path);
  if (r != 0) {
    resp_free(cfg);
    return NULL;
  }
  resp_object *sec = resp_map_get(cfg, section);
  resp_object *copy = sec ? resp_deep_copy(sec) : NULL;
  resp_free(cfg);
  return copy;
}

resp_object *config_key_get_path(const char *path, const char *section, const char *key) {
  if (!path || !section || !key) return NULL;
  resp_object *sec = config_section_get_path(path, section);
  if (!sec || sec->type != RESPT_ARRAY) {
    resp_free(sec);
    return NULL;
  }
  resp_object *val = NULL;
  for (size_t i = 0; i + 1 < sec->u.arr.n; i += 2) {
    if (sec->u.arr.elem[i].type == RESPT_BULK &&
        strcmp(sec->u.arr.elem[i].u.s, key) == 0) {
      val = resp_deep_copy(&sec->u.arr.elem[i + 1]);
      break;
    }
  }
  return val;
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