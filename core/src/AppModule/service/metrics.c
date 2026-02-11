/*
 * Metrics module: registers metrics.* commands with the API server.
 *
 * Exports read-only PBX state (calls, extensions, trunks) and
 * maintains call load-average state (EMA 1/5/15 min).
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#include "rxi/log.h"
#include "config.h"
#include "PluginModule/plugin.h"
#include "AppModule/service/api.h"
#include "common/pt.h"
#include "AppModule/service/metrics.h"
#include "AppModule/call.h"
#include "AppModule/registration.h"
#include "AppModule/trunk_reg.h"

/* EMA decay constants: exp(-1/N) for N seconds in the window */

#define EMA_1   0.9833333333  /* exp(-1/60)  */
#define EMA_5   0.9966666667  /* exp(-1/300) */
#define EMA_15  0.9988888889  /* exp(-1/900) */

/* Module state */

static int    active_calls = 0;
static double load_1  = 0.0;
static double load_5  = 0.0;
static double load_15 = 0.0;
static time_t last_tick = 0;
static time_t last_reconcile = 0;

/* Helpers */

static size_t count_calls(void) {
  size_t n = 0;
  for (call_t *c = call_first(); c; c = c->next) n++;
  return n;
}

/* Write one call as a flat map array (alternating key-value pairs) */
static bool write_call_map(api_client_t *c, call_t *call) {
  if (!api_write_array(c, 20)) return false;
  if (!api_write_kv(c, "call_id", call->call_id)) return false;
  if (!api_write_kv(c, "direction", call->direction ? call->direction : "")) return false;
  if (!api_write_kv(c, "source", call->source_str ? call->source_str : "")) return false;
  if (!api_write_kv(c, "destination", call->dest_str ? call->dest_str : "")) return false;
  if (!api_write_kv(c, "trunk", call->trunk_name ? call->trunk_name : "")) return false;
  if (!api_write_kv_int(c, "answered", call->answered)) return false;
  if (!api_write_kv_time(c, "created_at", (long)call->created_at)) return false;
  if (!api_write_kv_time(c, "answered_at", (long)call->answered_at)) return false;
  if (!api_write_kv_int(c, "forks", (int)call->n_forks)) return false;
  if (!api_write_kv_int(c, "pending", (int)call->n_pending_exts)) return false;
  return true;
}

/* Write one extension from registration (metrics uses registration list only) */
static bool write_extension_map(api_client_t *c, ext_reg_t *reg) {
  const char *contact = reg->contact ? reg->contact : "";
  const char *trunk = reg->trunk_name ? reg->trunk_name : "";
  if (!api_write_array(c, 12)) return false;
  if (!api_write_kv(c, "number", reg->number ? reg->number : "")) return false;
  if (!api_write_kv(c, "name", "")) return false; /* from registration only */
  if (!api_write_kv_int(c, "registered", 1)) return false;
  if (!api_write_kv(c, "contact", contact)) return false;
  if (!api_write_kv(c, "trunk", trunk)) return false;
  if (!api_write_kv_time(c, "expires", (long)reg->expires)) return false;
  return true;
}

/* Write one trunk by name (reads section from live config for display) */
static bool write_trunk_map(api_client_t *c, const char *trunk_name) {
  char section[128];
  snprintf(section, sizeof(section), "trunk:%s", trunk_name);
  resp_object *map = config_section_get(section);
  int available = trunk_reg_is_available(trunk_name);
  if (!map || map->type != RESPT_ARRAY) {
    if (map) resp_free(map);
    return false;
  }
  const char *host = resp_map_get_string(map, "host");
  const char *port = resp_map_get_string(map, "port");
  const char *group = resp_map_get_string(map, "group");
  const char *cid = resp_map_get_string(map, "cid");
  const char *cid_name = resp_map_get_string(map, "cid_name");
  if (!api_write_array(c, 18)) { resp_free(map); return false; }
  if (!api_write_kv(c, "name", trunk_name)) { resp_free(map); return false; }
  if (!api_write_kv(c, "host", host ? host : "")) { resp_free(map); return false; }
  if (!api_write_kv(c, "port", port ? port : "")) { resp_free(map); return false; }
  if (!api_write_kv_int(c, "available", available)) { resp_free(map); return false; }
  if (!api_write_kv(c, "group_prefix", group ? group : "")) { resp_free(map); return false; }
  if (!api_write_kv(c, "cid", cid ? cid : "")) { resp_free(map); return false; }
  if (!api_write_kv(c, "cid_name", cid_name ? cid_name : "")) { resp_free(map); return false; }
  resp_free(map);
  return true;
}

/* Command handlers */

static bool cmd_metrics_keys(api_client_t *c, char **args, int nargs) {
  (void)args; (void)nargs;
  if (!api_write_array(c, 4)) return false;
  if (!api_write_bulk_cstr(c, "calls")) return false;
  if (!api_write_bulk_cstr(c, "extensions")) return false;
  if (!api_write_bulk_cstr(c, "trunks")) return false;
  if (!api_write_bulk_cstr(c, "load")) return false;
  return true;
}

/* Count unique trunk names in registration list */
static size_t count_unique_trunks(ext_reg_t **regs, size_t n) {
  size_t u = 0;
  for (size_t i = 0; i < n; i++) {
    const char *t = regs[i]->trunk_name ? regs[i]->trunk_name : "";
    if (!t[0]) continue;
    size_t j;
    for (j = 0; j < i; j++) {
      const char *tj = regs[j]->trunk_name ? regs[j]->trunk_name : "";
      if (strcmp(tj, t) == 0) break;
    }
    if (j == i) u++;
  }
  return u;
}

static bool cmd_metrics_llen(api_client_t *c, char **args, int nargs) {
  if (nargs != 2)
    return api_write_err(c, "wrong number of arguments for 'metrics.llen' command");
  const char *key = args[1];
  if (strcasecmp(key, "calls") == 0)
    return api_write_int(c, (int)count_calls());
  if (strcasecmp(key, "extensions") == 0) {
    ext_reg_t **regs = NULL;
    size_t n = registration_get_regs(NULL, NULL, &regs);
    bool ok = api_write_int(c, (int)n);
    if (regs) free(regs);
    return ok;
  }
  if (strcasecmp(key, "trunks") == 0) {
    ext_reg_t **regs = NULL;
    size_t n = registration_get_regs(NULL, NULL, &regs);
    size_t u = count_unique_trunks(regs, n);
    bool ok = api_write_int(c, (int)u);
    if (regs) free(regs);
    return ok;
  }
  return api_write_err(c, "no such key");
}

static bool cmd_metrics_lrange(api_client_t *c, char **args, int nargs) {
  if (nargs != 4)
    return api_write_err(c, "wrong number of arguments for 'metrics.lrange' command");
  const char *key = args[1];
  int start = atoi(args[2]);
  int stop  = atoi(args[3]);

  if (strcasecmp(key, "calls") == 0) {
    size_t total = count_calls();
    if (start < 0) start = (int)total + start;
    if (stop  < 0) stop  = (int)total + stop;
    if (start < 0) start = 0;
    if (stop >= (int)total) stop = (int)total - 1;
    if (start > stop) return api_write_array(c, 0);
    size_t count = (size_t)(stop - start + 1);
    if (!api_write_array(c, count)) return false;
    size_t idx = 0;
    for (call_t *call = call_first(); call; call = call->next, idx++) {
      if (idx < (size_t)start) continue;
      if (idx > (size_t)stop) break;
      if (!write_call_map(c, call)) return false;
    }
    return true;
  }

  if (strcasecmp(key, "extensions") == 0) {
    ext_reg_t **regs = NULL;
    size_t total = registration_get_regs(NULL, NULL, &regs);
    if (start < 0) start = (int)total + start;
    if (stop  < 0) stop  = (int)total + stop;
    if (start < 0) start = 0;
    if (stop >= (int)total) stop = (int)total - 1;
    if (start > stop) { if (regs) free(regs); return api_write_array(c, 0); }
    size_t count = (size_t)(stop - start + 1);
    if (!api_write_array(c, count)) { if (regs) free(regs); return false; }
    for (int i = start; i <= stop && (size_t)i < total; i++) {
      if (!write_extension_map(c, regs[i])) { if (regs) free(regs); return false; }
    }
    if (regs) free(regs);
    return true;
  }

  if (strcasecmp(key, "trunks") == 0) {
    ext_reg_t **regs = NULL;
    size_t n = registration_get_regs(NULL, NULL, &regs);
    /* Build unique trunk names in order */
    const char **names = (const char **)malloc(n * sizeof(const char *));
    size_t u = 0;
    for (size_t i = 0; i < n && names; i++) {
      const char *t = regs[i]->trunk_name ? regs[i]->trunk_name : "";
      if (!t[0]) continue;
      size_t j;
      for (j = 0; j < u; j++) if (strcmp(names[j], t) == 0) break;
      if (j == u) names[u++] = t;
    }
    if (!names) { if (regs) free(regs); return false; }
    int total = (int)u;
    if (start < 0) start = total + start;
    if (stop  < 0) stop  = total + stop;
    if (start < 0) start = 0;
    if (stop >= total) stop = total - 1;
    if (start > stop) { free(names); if (regs) free(regs); return api_write_array(c, 0); }
    size_t count = (size_t)(stop - start + 1);
    if (!api_write_array(c, count)) { free(names); if (regs) free(regs); return false; }
    for (int i = start; i <= stop; i++) {
      if (!write_trunk_map(c, names[i])) { free(names); if (regs) free(regs); return false; }
    }
    free(names);
    if (regs) free(regs);
    return true;
  }

  return api_write_err(c, "no such key");
}

static bool cmd_metrics_get(api_client_t *c, char **args, int nargs) {
  if (nargs != 2)
    return api_write_err(c, "wrong number of arguments for 'metrics.get' command");
  const char *key = args[1];
  char buf[32];
  if (strcasecmp(key, "load:1") == 0) {
    snprintf(buf, sizeof(buf), "%.2f", load_1);
    return api_write_bulk_cstr(c, buf);
  }
  if (strcasecmp(key, "load:5") == 0) {
    snprintf(buf, sizeof(buf), "%.2f", load_5);
    return api_write_bulk_cstr(c, buf);
  }
  if (strcasecmp(key, "load:15") == 0) {
    snprintf(buf, sizeof(buf), "%.2f", load_15);
    return api_write_bulk_cstr(c, buf);
  }
  return api_write_nil(c);
}

/* Public API */

void metrics_init(void) {
  api_register_cmd("metrics.keys",   cmd_metrics_keys);
  api_register_cmd("metrics.llen",   cmd_metrics_llen);
  api_register_cmd("metrics.lrange", cmd_metrics_lrange);
  api_register_cmd("metrics.get",    cmd_metrics_get);
  last_tick = time(NULL);
  last_reconcile = last_tick;
  log_debug("metrics: commands registered");
}

static time_t next_metrics_tick = 0;

PT_THREAD(metrics_tick_pt(struct pt *pt, time_t loop_timestamp)) {
  PT_BEGIN(pt);
  for (;;) {
    PT_WAIT_UNTIL(pt, next_metrics_tick == 0 || loop_timestamp >= next_metrics_tick);
    next_metrics_tick = loop_timestamp + 1;

    time_t now = loop_timestamp;
    if (now > last_tick) {
      long elapsed = (long)(now - last_tick);
      if (elapsed > 60) elapsed = 60; /* cap catch-up */
      for (long s = 0; s < elapsed; s++) {
        load_1  = load_1  * EMA_1  + (double)active_calls * (1.0 - EMA_1);
        load_5  = load_5  * EMA_5  + (double)active_calls * (1.0 - EMA_5);
        load_15 = load_15 * EMA_15 + (double)active_calls * (1.0 - EMA_15);
      }
      last_tick = now;

      if (now - last_reconcile >= 900) {
        int real_count = 0;
        for (call_t *c = call_first(); c; c = c->next) {
          if (c->answered) real_count++;
        }
        if (real_count != active_calls) {
          log_debug("metrics: reconcile active_calls %d -> %d", active_calls, real_count);
          active_calls = real_count;
        }
        last_reconcile = now;
      }
    }
  }
  PT_END(pt);
}

void metrics_call_active(void) {
  active_calls++;
}

void metrics_call_inactive(void) {
  if (active_calls > 0) active_calls--;
}
