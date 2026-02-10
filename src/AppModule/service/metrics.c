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
#include "AppModule/service/api.h"
#include "AppModule/service/metrics.h"
#include "AppModule/call.h"
#include "AppModule/registration.h"
#include "AppModule/trunk_reg.h"

/* ---- EMA decay constants: exp(-1/N) for N seconds in the window ---- */

#define EMA_1   0.9833333333  /* exp(-1/60)  */
#define EMA_5   0.9966666667  /* exp(-1/300) */
#define EMA_15  0.9988888889  /* exp(-1/900) */

/* ---- Module state ---- */

static int    active_calls = 0;
static double load_1  = 0.0;
static double load_5  = 0.0;
static double load_15 = 0.0;
static time_t last_tick = 0;
static time_t last_reconcile = 0;

/* ---- Helpers ---- */

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
  if (!api_write_kv(c, "trunk", call->trunk ? call->trunk->name : "")) return false;
  if (!api_write_kv_int(c, "answered", call->answered)) return false;
  if (!api_write_kv_time(c, "created_at", (long)call->created_at)) return false;
  if (!api_write_kv_time(c, "answered_at", (long)call->answered_at)) return false;
  if (!api_write_kv_int(c, "forks", (int)call->n_forks)) return false;
  if (!api_write_kv_int(c, "pending", (int)call->n_pending_exts)) return false;
  return true;
}

/* Write one extension as a flat map array */
static bool write_extension_map(api_client_t *c, config_extension *ext) {
  ext_reg_t *reg = registration_get_by_number(NULL, ext->number);
  const char *contact = reg ? (reg->contact ? reg->contact : "") : "";
  const char *trunk = reg ? (reg->trunk_name ? reg->trunk_name : "") : "";
  time_t expires = reg ? reg->expires : 0;
  if (!api_write_array(c, 12)) return false;
  if (!api_write_kv(c, "number", ext->number)) return false;
  if (!api_write_kv(c, "name", ext->name ? ext->name : "")) return false;
  if (!api_write_kv_int(c, "registered", reg ? 1 : 0)) return false;
  if (!api_write_kv(c, "contact", contact)) return false;
  if (!api_write_kv(c, "trunk", trunk)) return false;
  if (!api_write_kv_time(c, "expires", (long)expires)) return false;
  return true;
}

/* Write one trunk as a flat map array */
static bool write_trunk_map(api_client_t *c, config_trunk *t) {
  int available = trunk_reg_is_available(t->name);
  if (!api_write_array(c, 18)) return false;
  if (!api_write_kv(c, "name", t->name)) return false;
  if (!api_write_kv(c, "host", t->host ? t->host : "")) return false;
  if (!api_write_kv(c, "port", t->port ? t->port : "")) return false;
  if (!api_write_kv_int(c, "available", available)) return false;
  if (!api_write_kv(c, "group_prefix", t->group_prefix ? t->group_prefix : "")) return false;
  if (!api_write_kv(c, "cid", t->cid ? t->cid : "")) return false;
  if (!api_write_kv(c, "cid_name", t->cid_name ? t->cid_name : "")) return false;
  if (!api_write_kv_int(c, "did_count", (int)t->did_count)) return false;
  if (!api_write_kv_int(c, "filter_incoming", t->filter_incoming)) return false;
  return true;
}

/* ---- Command handlers ---- */

static bool cmd_metrics_keys(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  (void)cfg; (void)args; (void)nargs;
  if (!api_write_array(c, 4)) return false;
  if (!api_write_bulk_cstr(c, "calls")) return false;
  if (!api_write_bulk_cstr(c, "extensions")) return false;
  if (!api_write_bulk_cstr(c, "trunks")) return false;
  if (!api_write_bulk_cstr(c, "load")) return false;
  return true;
}

static bool cmd_metrics_llen(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  if (nargs != 2)
    return api_write_err(c, "wrong number of arguments for 'metrics.llen' command");
  const char *key = args[1];
  if (strcasecmp(key, "calls") == 0)
    return api_write_int(c, (int)count_calls());
  if (strcasecmp(key, "extensions") == 0)
    return api_write_int(c, (int)cfg->extension_count);
  if (strcasecmp(key, "trunks") == 0)
    return api_write_int(c, (int)cfg->trunk_count);
  return api_write_err(c, "no such key");
}

static bool cmd_metrics_lrange(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
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
    int total = (int)cfg->extension_count;
    if (start < 0) start = total + start;
    if (stop  < 0) stop  = total + stop;
    if (start < 0) start = 0;
    if (stop >= total) stop = total - 1;
    if (start > stop) return api_write_array(c, 0);
    size_t count = (size_t)(stop - start + 1);
    if (!api_write_array(c, count)) return false;
    for (int i = start; i <= stop; i++) {
      if (!write_extension_map(c, &cfg->extensions[i])) return false;
    }
    return true;
  }

  if (strcasecmp(key, "trunks") == 0) {
    int total = (int)cfg->trunk_count;
    if (start < 0) start = total + start;
    if (stop  < 0) stop  = total + stop;
    if (start < 0) start = 0;
    if (stop >= total) stop = total - 1;
    if (start > stop) return api_write_array(c, 0);
    size_t count = (size_t)(stop - start + 1);
    if (!api_write_array(c, count)) return false;
    for (int i = start; i <= stop; i++) {
      if (!write_trunk_map(c, &cfg->trunks[i])) return false;
    }
    return true;
  }

  return api_write_err(c, "no such key");
}

static bool cmd_metrics_get(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  (void)cfg;
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

/* ---- Public API ---- */

void metrics_init(struct upbx_config *cfg) {
  (void)cfg;
  api_register_cmd("metrics.keys",   cmd_metrics_keys);
  api_register_cmd("metrics.llen",   cmd_metrics_llen);
  api_register_cmd("metrics.lrange", cmd_metrics_lrange);
  api_register_cmd("metrics.get",    cmd_metrics_get);
  last_tick = time(NULL);
  last_reconcile = last_tick;
  log_debug("metrics: commands registered");
}

void metrics_tick(void) {
  time_t now = time(NULL);
  if (now <= last_tick) return;

  long elapsed = (long)(now - last_tick);
  if (elapsed > 60) elapsed = 60; /* cap catch-up */
  for (long s = 0; s < elapsed; s++) {
    load_1  = load_1  * EMA_1  + (double)active_calls * (1.0 - EMA_1);
    load_5  = load_5  * EMA_5  + (double)active_calls * (1.0 - EMA_5);
    load_15 = load_15 * EMA_15 + (double)active_calls * (1.0 - EMA_15);
  }
  last_tick = now;

  /* Periodic reconciliation: every 15 minutes, do a real count */
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

void metrics_call_active(void) {
  active_calls++;
}

void metrics_call_inactive(void) {
  if (active_calls > 0) active_calls--;
}
