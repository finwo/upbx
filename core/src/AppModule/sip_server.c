/*
 * SIP server: listen on UDP, receive datagrams, parse SIP with internal parser,
 * handle REGISTER (extension auth, registration via registration.c) and INVITE (call routing).
 * Single-threaded: select() loop and protothreads (common/pt.h); UDP sockets are non-blocking.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

#include "common/pt.h"
#include "common/socket_util.h"
#include "common/hexdump.h"
#include "common/digest_auth.h"
#include "rxi/log.h"
#include "config.h"
#include "AppModule/plugin.h"
#include "PluginModule/plugin.h"
#include "AppModule/sip_server.h"
#include "AppModule/trunk_reg.h"
#include "AppModule/sip_parse.h"
#include "AppModule/util/sdp_parse.h"
#include "AppModule/call.h"
#include "AppModule/registration.h"
#include "AppModule/service/api.h"
#include "AppModule/service/metrics.h"

#define SIP_READ_BUF_SIZE  (64 * 1024)
#define AUTH_REALM         "upbx"

static char *auth_generate_nonce(void) {
  static char nonce[48];
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  /* Unquoted so digest calculation uses the same value we send and we parse back */
  snprintf(nonce, sizeof(nonce), "%lx%lx%x",
      (long)ts.tv_sec, (long)ts.tv_nsec, (unsigned)rand());
  return nonce;
}

/* Registration state is managed by AppModule/registration.c.
 * See registration.h for the ext_reg_t struct and query/update API. */

static int ext_pattern_match(const char *pattern, const char *number);

/* Get extension section from live config: exact ext:<number> first, then first pattern match in config order. Caller resp_free. If section_name_out non-NULL, copy the section name used (e.g. "ext:206" or "ext:20x"). */
static resp_object *get_extension_section(const char *number, char *section_name_out, size_t section_name_size) {
  if (!number || !number[0]) return NULL;
  char section[128];
  snprintf(section, sizeof(section), "ext:%s", number);
  resp_object *exact = config_section_get(section);
  if (exact && exact->type == RESPT_ARRAY) {
    if (section_name_out && section_name_size) {
      strncpy(section_name_out, section, section_name_size - 1);
      section_name_out[section_name_size - 1] = '\0';
    }
    return exact;
  }
  if (exact) { resp_free(exact); exact = NULL; }

  resp_object *list = config_sections_list();
  if (!list || list->type != RESPT_ARRAY) {
    if (list) resp_free(list);
    return NULL;
  }
  for (size_t i = 0; i < list->u.arr.n; i++) {
    resp_object *e = &list->u.arr.elem[i];
    if ((e->type != RESPT_BULK && e->type != RESPT_SIMPLE) || !e->u.s) continue;
    if (strncmp(e->u.s, "ext:", 4) != 0) continue;
    const char *tail = e->u.s + 4;
    if (!ext_pattern_match(tail, number)) continue;
    resp_object *sec = config_section_get(e->u.s);
    if (sec && section_name_out && section_name_size) {
      strncpy(section_name_out, e->u.s, section_name_size - 1);
      section_name_out[section_name_size - 1] = '\0';
    }
    resp_free(list);
    return sec;
  }
  resp_free(list);
  return NULL;
}

static config_trunk *get_trunk_config(upbx_config *cfg, const char *name) {
  for (size_t i = 0; i < cfg->trunk_count; i++)
    if (strcmp(cfg->trunks[i].name, name) == 0)
      return &cfg->trunks[i];
  return NULL;
}

/* Decode %40 to @ in place (URI userinfo may be percent-encoded). Shrinks string. */
static void decode_percent_at_inplace(char *s) {
  char *w = s;
  for (const char *r = s; *r; r++) {
    if (r[0] == '%' && r[1] == '4' && r[2] == '0') {
      *w++ = '@';
      r += 2;
    } else
      *w++ = *r;
  }
  *w = '\0';
}

/* Return allocated prefix of username before first @ or %40 (caller frees). Used for Authorization username. */
static char *extension_part_from_username(const char *username) {
  if (!username) return NULL;
  const char *end = username;
  while (*end && *end != '@') {
    if (end[0] == '%' && end[1] == '4' && end[2] == '0') break;
    end++;
  }
  size_t n = (size_t)(end - username);
  char *out = malloc(n + 1);
  if (!out) return NULL;
  memcpy(out, username, n);
  out[n] = '\0';
  return out;
}

/* Resolve trunk for extension: by locality/group prefix, or first trunk when locality==0.
 * Returns NULL when no trunks are configured (ext-to-ext only). */
static config_trunk *resolve_trunk_for_extension(upbx_config *cfg, const char *ext_number) {
  if (!cfg || cfg->trunk_count == 0)
    return NULL;  /* no trunks → ext-to-ext only */
  if (cfg->locality == 0)
    return &cfg->trunks[0];  /* one big group: first trunk is representative */
  /* locality > 0: match by group prefix */
  size_t ext_len = ext_number ? strlen(ext_number) : 0;
  for (size_t i = 0; i < cfg->trunk_count; i++) {
    if (!cfg->trunks[i].group_prefix) continue;
    size_t pre_len = strlen(cfg->trunks[i].group_prefix);
    if (ext_len >= pre_len + (size_t)cfg->locality &&
        strncmp(ext_number, cfg->trunks[i].group_prefix, pre_len) == 0)
      return &cfg->trunks[i];
  }
  return NULL;  /* no matching group */
}

/* Find trunk that has this DID. */
static config_trunk *find_trunk_by_did(upbx_config *cfg, const char *did) {
  if (!did || !*did) return NULL;
  for (size_t i = 0; i < cfg->trunk_count; i++) {
    for (size_t j = 0; j < cfg->trunks[i].did_count; j++) {
      if (strcmp(cfg->trunks[i].dids[j], did) == 0)
        return &cfg->trunks[i];
    }
  }
  return NULL;
}

/* Collect all trunks in the same locality group as 'member'. Returns count written to out[]. */
static size_t get_group_trunks(upbx_config *cfg, config_trunk *member,
    config_trunk **out, size_t max_out) {
  if (!cfg || !member || !out || max_out == 0) return 0;
  size_t n = 0;
  if (cfg->locality == 0) {
    /* One big group: return ALL trunks. */
    for (size_t i = 0; i < cfg->trunk_count && n < max_out; i++)
      out[n++] = &cfg->trunks[i];
    return n;
  }
  /* locality > 0: match by group_prefix. */
  if (!member->group_prefix || !member->group_prefix[0]) {
    /* No prefix: trunk is alone in its group. */
    out[0] = member;
    return 1;
  }
  for (size_t i = 0; i < cfg->trunk_count && n < max_out; i++) {
    if (cfg->trunks[i].group_prefix &&
        strcmp(cfg->trunks[i].group_prefix, member->group_prefix) == 0)
      out[n++] = &cfg->trunks[i];
  }
  return n;
}

/* Collect all registered extensions across a locality group.
 * Allocates *out (caller frees). Returns extension count. */
static size_t get_group_regs(upbx_config *cfg, config_trunk *member,
    ext_reg_t ***out) {
  *out = NULL;
  config_trunk *group_trunks[64];
  size_t n_trunks = get_group_trunks(cfg, member, group_trunks, 64);
  if (n_trunks == 0) return 0;

  ext_reg_t **merged = NULL;
  size_t merged_n = 0;

  for (size_t t = 0; t < n_trunks; t++) {
    ext_reg_t **tregs = NULL;
    size_t tn = registration_get_regs(group_trunks[t]->name, NULL, &tregs);
    for (size_t i = 0; i < tn; i++) {
      /* De-duplicate by extension number. */
      int dup = 0;
      for (size_t j = 0; j < merged_n; j++) {
        if (merged[j]->number && tregs[i]->number &&
            strcmp(merged[j]->number, tregs[i]->number) == 0) { dup = 1; break; }
      }
      if (!dup) {
        ext_reg_t **tmp = realloc(merged, (merged_n + 1) * sizeof(ext_reg_t *));
        if (tmp) { merged = tmp; merged[merged_n++] = tregs[i]; }
      }
    }
    free(tregs);
  }
  /* When locality == 0 (one big group), also include trunk-less extensions. */
  if (cfg->locality == 0) {
    ext_reg_t **nregs = NULL;
    size_t nn = registration_get_regs("", NULL, &nregs);
    for (size_t i = 0; i < nn; i++) {
      int dup = 0;
      for (size_t j = 0; j < merged_n; j++) {
        if (merged[j]->number && nregs[i]->number &&
            strcmp(merged[j]->number, nregs[i]->number) == 0) { dup = 1; break; }
      }
      if (!dup) {
        ext_reg_t **tmp = realloc(merged, (merged_n + 1) * sizeof(ext_reg_t *));
        if (tmp) { merged = tmp; merged[merged_n++] = nregs[i]; }
      }
    }
    free(nregs);
  }
  *out = merged;
  return merged_n;
}

/* Check if a number is in the emergency list. */
static int is_emergency_number(upbx_config *cfg, const char *number) {
  if (!number || !number[0]) return 0;
  for (size_t i = 0; i < cfg->emergency_count; i++)
    if (strcmp(cfg->emergency[i], number) == 0) return 1;
  return 0;
}

/* Pattern match: 'x'/'X' matches any digit. Returns 1 on match. */
static int ext_pattern_match(const char *pattern, const char *number) {
  for (; *pattern && *number; pattern++, number++) {
    if (*pattern == 'x' || *pattern == 'X') {
      if (*number < '0' || *number > '9') return 0;
    } else if (*pattern != *number) {
      return 0;
    }
  }
  return (*pattern == '\0' && *number == '\0');
}

/* get_extension_section() above does exact then first pattern match. Use it for both lookup types. */

/* Regex match: return pointer to regmatch_t array on match, NULL otherwise. First-match only (NMATCHES). */
#define REWRITE_NMATCHES 10
static regmatch_t *regex_rmatch(const char *buf, int size, regex_t *re) {
  static regmatch_t pm[REWRITE_NMATCHES];
  (void)size;
  if (regexec(re, buf, REWRITE_NMATCHES, pm, 0) != 0)
    return NULL;
  return &pm[0];
}

/* Regex replace in buf using pmatch; rp may contain \1..\9. Returns 0 on success, -1 on failure. */
static int regex_rreplace(char *buf, int size, regex_t *re, regmatch_t pmatch[], char *rp) {
  char *pos;
  int sub, so, n;
  for (pos = rp; *pos; pos++) {
    if (*pos == '\\' && *(pos + 1) > '0' && *(pos + 1) <= '9') {
      so = pmatch[*(pos + 1) - 48].rm_so;
      n = pmatch[*(pos + 1) - 48].rm_eo - so;
      if (so < 0 || (int)(strlen(rp) + n - 1) > size) return -1;
      memmove(pos + n, pos + 2, strlen(pos) - 1);
      memmove(pos, buf + so, (size_t)n);
      pos = pos + n - 2;
    }
  }
  sub = pmatch[1].rm_so;
  for (pos = buf; regexec(re, pos, 1, pmatch, 0) == 0; ) {
    n = pmatch[0].rm_eo - pmatch[0].rm_so;
    pos += pmatch[0].rm_so;
    if ((int)(strlen(buf) - n + strlen(rp)) > size)
      return -1;
    memmove(pos + strlen(rp), pos + n, strlen(pos) - n + 1);
    memmove(pos, rp, strlen(rp));
    pos += strlen(rp);
    if (sub >= 0) break;
  }
  return 0;
}

/* Apply trunk rewrite rules (first match wins). Output is always null-terminated. */
static void apply_trunk_rewrites(config_trunk *trunk, const char *input, char *output, size_t out_size) {
  log_trace("apply_trunk_rewrites: trunk=%s input=%s", trunk ? trunk->name : "(null)", input ? input : "");
  char work[256];
  if (!trunk || !trunk->rewrite_regex || trunk->rewrite_count == 0 || !output || out_size == 0) {
    if (output && out_size) { strncpy(output, input ? input : "", out_size - 1); output[out_size - 1] = '\0'; }
    return;
  }
  strncpy(work, input ? input : "", sizeof(work) - 1);
  work[sizeof(work) - 1] = '\0';
  regex_t *re = (regex_t *)trunk->rewrite_regex;
  for (size_t i = 0; i < trunk->rewrite_count; i++) {
    regmatch_t *pmatch = regex_rmatch(work, (int)sizeof(work), &re[i]);
    if (pmatch) {
      char replace[256];
      strncpy(replace, trunk->rewrites[i].replace ? trunk->rewrites[i].replace : "", sizeof(replace) - 1);
      replace[sizeof(replace) - 1] = '\0';
      if (regex_rreplace(work, (int)sizeof(work), &re[i], pmatch, replace) == 0)
        break;
    }
  }
  size_t len = strlen(work);
  if (len >= out_size) len = out_size - 1;
  memcpy(output, work, len);
  output[len] = '\0';
}

/* Trunk lookup for extension is now registration_get_trunk_for_ext() in registration.c. */

/* Build one map for extension.list: key "extensions" = array of maps { number, name, trunk }. Caller resp_frees. */
static resp_object *build_extension_list_map(upbx_config *cfg) {
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "extensions") != 0) { resp_free(map); return NULL; }
  resp_object *arr = resp_array_init();
  if (!arr) { resp_free(map); return NULL; }
  for (size_t i = 0; i < cfg->extension_count; i++) {
    config_extension *e = &cfg->extensions[i];
    const char *trunk_str = registration_get_trunk_for_ext(e->number);
    resp_object *em = resp_array_init();
    if (!em) { resp_free(arr); resp_free(map); return NULL; }
    if (resp_array_append_bulk(em, "number") != 0 || resp_array_append_bulk(em, e->number ? e->number : "") != 0 ||
        resp_array_append_bulk(em, "name") != 0 || resp_array_append_bulk(em, e->name ? e->name : "") != 0 ||
        resp_array_append_bulk(em, "trunk") != 0 || resp_array_append_bulk(em, trunk_str ? trunk_str : "") != 0) {
      resp_free(em);
      resp_free(arr);
      resp_free(map);
      return NULL;
    }
    if (resp_array_append_obj(arr, em) != 0) { resp_free(em); resp_free(arr); resp_free(map); return NULL; }
  }
  if (resp_array_append_obj(map, arr) != 0) { resp_free(arr); resp_free(map); return NULL; }
  return map;
}

/* Build one map for trunk.list: key "trunks" = array of maps { name, group_prefix, dids, cid, extensions }. Caller resp_frees. */
static resp_object *build_trunk_list_map(upbx_config *cfg) {
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "trunks") != 0) { resp_free(map); return NULL; }
  resp_object *arr = resp_array_init();
  if (!arr) { resp_free(map); return NULL; }
  for (size_t i = 0; i < cfg->trunk_count; i++) {
    config_trunk *t = &cfg->trunks[i];
    resp_object *tm = resp_array_init();
    if (!tm) { resp_free(arr); resp_free(map); return NULL; }
    if (resp_array_append_bulk(tm, "name") != 0 || resp_array_append_bulk(tm, t->name ? t->name : "") != 0 ||
        resp_array_append_bulk(tm, "group_prefix") != 0 || resp_array_append_bulk(tm, t->group_prefix ? t->group_prefix : "") != 0 ||
        resp_array_append_bulk(tm, "dids") != 0) {
      resp_free(tm);
      resp_free(arr);
      resp_free(map);
      return NULL;
    }
    resp_object *dids_arr = resp_array_init();
    if (!dids_arr) { resp_free(tm); resp_free(arr); resp_free(map); return NULL; }
    for (size_t d = 0; d < t->did_count; d++) {
      if (resp_array_append_bulk(dids_arr, t->dids[d] ? t->dids[d] : "") != 0) {
        resp_free(dids_arr);
        resp_free(tm);
        resp_free(arr);
        resp_free(map);
        return NULL;
      }
    }
    if (resp_array_append_obj(tm, dids_arr) != 0) { resp_free(dids_arr); resp_free(tm); resp_free(arr); resp_free(map); return NULL; }
    if (resp_array_append_bulk(tm, "cid") != 0 || resp_array_append_bulk(tm, t->cid ? t->cid : "") != 0 ||
        resp_array_append_bulk(tm, "extensions") != 0) {
      resp_free(tm);
      resp_free(arr);
      resp_free(map);
      return NULL;
    }
    ext_reg_t **tregs = NULL;
    size_t treg_count = registration_get_regs(t->name, NULL, &tregs);
    resp_object *exts_arr = resp_array_init();
    if (!exts_arr) { resp_free(tm); resp_free(arr); resp_free(map); if (tregs) free(tregs); return NULL; }
    for (size_t r = 0; r < treg_count; r++) {
      if (resp_array_append_bulk(exts_arr, tregs[r]->number ? tregs[r]->number : "") != 0) {
        resp_free(exts_arr);
        resp_free(tm);
        resp_free(arr);
        resp_free(map);
        if (tregs) free(tregs);
        return NULL;
      }
    }
    if (tregs) free(tregs);
    if (resp_array_append_obj(tm, exts_arr) != 0) { resp_free(exts_arr); resp_free(tm); resp_free(arr); resp_free(map); return NULL; }
    if (resp_array_append_obj(arr, tm) != 0) { resp_free(tm); resp_free(arr); resp_free(map); return NULL; }
  }
  if (resp_array_append_obj(map, arr) != 0) { resp_free(arr); resp_free(map); return NULL; }
  return map;
}

/* Notify plugins of extension list and trunk list (one map each). */
static void notify_extension_and_trunk_lists(upbx_config *cfg) {
  if (plugin_count() == 0) return;
  size_t i;

  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "extension.list")) break;
  }
  if (i < plugin_count()) {
    resp_object *map = build_extension_list_map(cfg);
    if (map) {
      plugin_notify_event("extension.list", 1, (const resp_object *const *)&map);
      resp_free(map);
    }
  }

  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "trunk.list")) break;
  }
  if (i < plugin_count()) {
    resp_object *map = build_trunk_list_map(cfg);
    if (map) {
      plugin_notify_event("trunk.list", 1, (const resp_object *const *)&map);
      resp_free(map);
    }
  }
}

static int sockaddr_match(const struct sockaddr_storage *a, socklen_t alen,
                          const struct sockaddr_storage *b, socklen_t blen) {
  if (alen != blen) return 0;
  return memcmp(a, b, (size_t)alen) == 0;
}

/* Build a SIP Request-URI from a sockaddr_storage + user string.
 * Returns 0 on success, -1 if not AF_INET. */
static int fork_uri_from_addr(const struct sockaddr_storage *addr, const char *user,
                              char *uri_out, size_t uri_size) {
  if (addr->ss_family != AF_INET) return -1;
  const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
  char ip[INET_ADDRSTRLEN], port_s[16];
  inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
  snprintf(port_s, sizeof(port_s), "%u", (unsigned)ntohs(sin->sin_port));
  sip_format_request_uri(user ? user : "", ip, port_s, uri_out, uri_size);
  return 0;
}

/* Notify plugins of call.answer (direction, call_id, source, destination). */
/* Build one map for call.answer: direction, call_id, source, destination. Caller resp_frees. */
static resp_object *build_call_answer_map(const char *direction, const char *call_id, const char *source, const char *destination) {
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "direction") != 0 || resp_array_append_bulk(map, direction ? direction : "") != 0 ||
      resp_array_append_bulk(map, "call_id") != 0 || resp_array_append_bulk(map, call_id ? call_id : "") != 0 ||
      resp_array_append_bulk(map, "source") != 0 || resp_array_append_bulk(map, source ? source : "") != 0 ||
      resp_array_append_bulk(map, "destination") != 0 || resp_array_append_bulk(map, destination ? destination : "") != 0) {
    resp_free(map);
    return NULL;
  }
  return map;
}

/* Build one map for call.hangup: call_id, source, destination, duration_sec. Caller resp_frees. */
static resp_object *build_call_hangup_map(const char *call_id, const char *source, const char *destination, int duration_sec) {
  char dur_buf[32];
  snprintf(dur_buf, sizeof(dur_buf), "%d", duration_sec);
  resp_object *map = resp_array_init();
  if (!map) return NULL;
  if (resp_array_append_bulk(map, "call_id") != 0 || resp_array_append_bulk(map, call_id ? call_id : "") != 0 ||
      resp_array_append_bulk(map, "source") != 0 || resp_array_append_bulk(map, source ? source : "") != 0 ||
      resp_array_append_bulk(map, "destination") != 0 || resp_array_append_bulk(map, destination ? destination : "") != 0 ||
      resp_array_append_bulk(map, "duration_sec") != 0 || resp_array_append_bulk(map, dur_buf) != 0) {
    resp_free(map);
    return NULL;
  }
  return map;
}

static void notify_call_answer(const char *direction, const char *call_id, const char *source, const char *destination) {
  size_t i;
  if (plugin_count() == 0) return;
  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "call.answer")) break;
  }
  if (i >= plugin_count()) return;
  log_debug("call.answer: notifying plugins, call=%.32s %s -> %s (%s)", call_id ? call_id : "", source ? source : "", destination ? destination : "", direction ? direction : "");
  resp_object *map = build_call_answer_map(direction, call_id, source, destination);
  if (map) {
    plugin_notify_event("call.answer", 1, (const resp_object *const *)&map);
    resp_free(map);
  }
}

static void notify_call_hangup(const char *call_id, const char *source, const char *destination, int duration_sec) {
  size_t i;
  if (plugin_count() == 0) return;
  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "call.hangup")) break;
  }
  if (i >= plugin_count()) return;
  log_debug("call.hangup: notifying plugins, call=%.32s %s -> %s (%ds)", call_id ? call_id : "", source ? source : "", destination ? destination : "", duration_sec);
  resp_object *map = build_call_hangup_map(call_id, source, destination, duration_sec);
  if (map) {
    plugin_notify_event("call.hangup", 1, (const resp_object *const *)&map);
    resp_free(map);
  }
}

/* Pre-remove callback: fires call.hangup plugin event for every call removal,
 * including timeout aging (which previously bypassed notifications). */
static void call_pre_remove_handler(call_t *call) {
  if (!call) return;
  if (call->answered)
    metrics_call_inactive();
  int duration = 0;
  if (call->answered && call->answered_at > 0)
    duration = (int)(time(NULL) - call->answered_at);
  log_info("call hangup: %.32s %s -> %s (duration %ds)", call->call_id,
           call->source_str ? call->source_str : "", call->dest_str ? call->dest_str : "", duration);
  notify_call_hangup(call->call_id, call->source_str, call->dest_str, duration);
}

/* Clear all pending extensions from a call (free strings, reset count). */
static void clear_pending_exts(call_t *call) {
  for (size_t i = 0; i < call->n_pending_exts; i++)
    free(call->pending_exts[i]);
  call->n_pending_exts = 0;
}

/* Registration queries: see registration.h. */

/* Parse Contact URI string to host and port. Contact may be "sip:user@host:port",
 * "<sip:...>", or "display-name" <sip:...>. Return 0 on success. */
static int contact_to_host_port(const char *contact, char *host, size_t host_size, char *port, size_t port_size) {
  const char *s = contact;
  if (!s || !host || host_size == 0 || !port || port_size == 0) return -1;
  /* Skip optional display name and find the '<' that starts the URI. */
  const char *lt = strchr(s, '<');
  if (lt) {
    s = lt + 1;
  } else {
    while (*s == ' ' || *s == '\t') s++;
  }
  if (strncasecmp(s, "sip:", 4) != 0) return -1;
  s += 4;
  const char *at = strchr(s, '@');
  if (!at) return -1;
  s = at + 1;
  const char *colon = strrchr(s, ':');
  if (colon && colon > s) {
    size_t host_len = (size_t)(colon - s);
    if (host_len >= host_size) return -1;
    memcpy(host, s, host_len);
    host[host_len] = '\0';
    const char *port_start = colon + 1;
    const char *end = port_start;
    while (*end && *end != '>' && *end != ';' && *end != ' ') end++;
    if ((size_t)(end - port_start) >= port_size) return -1;
    memcpy(port, port_start, (size_t)(end - port_start));
    port[end - port_start] = '\0';
  } else {
    const char *end = s;
    while (*end && *end != '>' && *end != ';' && *end != ' ' && *end != ':') end++;
    if ((size_t)(end - s) >= host_size) return -1;
    memcpy(host, s, (size_t)(end - s));
    host[end - s] = '\0';
    snprintf(port, port_size, "5060");
  }
  return 0;
}

/* When username_for_ha1 is non-NULL, use it for digest (original as received); else use username parsed from header. */
static int verify_digest(const char *req_buf, size_t req_len, const char *method, const char *password,
    const char *expected_realm, const char *username_for_ha1) {
  char *user = NULL, *realm = NULL, *nonce = NULL, *cnonce = NULL, *nc = NULL, *qop = NULL, *uri = NULL, *client_response = NULL;
  if (!sip_parse_authorization_digest(req_buf, req_len, &user, &realm, &nonce, &cnonce, &nc, &qop, &uri, &client_response))
    return 0;
  if (!realm || !nonce || !uri || !client_response) {
    free(user); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(client_response);
    return 0;
  }
  if (!user && !username_for_ha1) {
    free(user); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(client_response);
    return 0;
  }
  if (strcmp(realm, expected_realm) != 0) {
    free(user); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(client_response);
    return 0;
  }
  const char *digest_user = (username_for_ha1 && username_for_ha1[0]) ? username_for_ha1 : (user ? user : "");
  log_debug("REGISTER digest: username=\"%s\"", digest_user);
  HASHHEX ha1, response_hex;
  digest_calc_ha1("MD5", digest_user, realm, password, nonce, cnonce, ha1);
  HASHHEX hent = "";
  /* Server uses legacy only (RFC 2069): response = MD5(HA1:nonce:HA2). Ignore qop/nc/cnonce for verification. */
  digest_calc_response(ha1, nonce, NULL, NULL, NULL, method, uri, hent, response_hex);
  int ok = (strcasecmp((char *)response_hex, client_response) == 0);
  if (!ok)
    log_debug("REGISTER digest: mismatch calculated=\"%s\" client=\"%s\"", (char *)response_hex, client_response ? client_response : "(null)");
  free(user); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(client_response);
  return ok;
}

/* Send context: UDP (response sent back to peer via sendto). */
typedef struct {
  int sockfd;
  struct sockaddr_storage peer;
  socklen_t peerlen;
} sip_send_ctx;

static const char *reason_phrase(int code);

static void send_response_buf(sip_send_ctx *ctx, const char *buf, size_t len) {
  if (!ctx || !buf) return;
  sendto(ctx->sockfd, buf, len, 0, (struct sockaddr *)&ctx->peer, ctx->peerlen);
}

/* Build SIP response from request: parse headers from req, build from parts. Caller frees returned buffer. */
static char *build_reply(const char *req_buf, size_t req_len, int code, int copy_contact, int add_wwa, size_t *out_len) {
  char via_buf[512], from_buf[384], to_buf[384], call_id_buf[256], cseq_buf[64], contact_buf[256];
  via_buf[0] = from_buf[0] = to_buf[0] = call_id_buf[0] = cseq_buf[0] = contact_buf[0] = '\0';
  sip_header_copy(req_buf, req_len, "Via", via_buf, sizeof(via_buf));
  sip_header_copy(req_buf, req_len, "From", from_buf, sizeof(from_buf));
  sip_header_copy(req_buf, req_len, "To", to_buf, sizeof(to_buf));
  sip_header_copy(req_buf, req_len, "Call-ID", call_id_buf, sizeof(call_id_buf));
  sip_header_copy(req_buf, req_len, "CSeq", cseq_buf, sizeof(cseq_buf));
  if (copy_contact) sip_header_copy(req_buf, req_len, "Contact", contact_buf, sizeof(contact_buf));
  const char *reason = reason_phrase(code);
  const char *extra[2];
  size_t n_extra = 0;
  if (add_wwa) {
    extra[0] = sip_build_www_authenticate(AUTH_REALM, auth_generate_nonce());
    if (extra[0]) n_extra = 1;
  }
  char *resp = sip_build_response_parts(code, reason,
    via_buf[0] ? via_buf : NULL, from_buf[0] ? from_buf : NULL, to_buf[0] ? to_buf : NULL,
    call_id_buf[0] ? call_id_buf : NULL, cseq_buf[0] ? cseq_buf : NULL,
    contact_buf[0] ? contact_buf : NULL, "upbx",
    NULL, 0, n_extra ? extra : NULL, n_extra, out_len);
  if (add_wwa && extra[0]) free((void *)extra[0]);
  return resp;
}

/* Convenience wrapper: build a SIP reply and send it to the peer in ctx.
 * Handles allocation, send, and free in one call. */
static void send_reply(sip_send_ctx *ctx, const char *buf, size_t len,
                       int code, int copy_contact, int add_wwa) {
  char *r = build_reply(buf, len, code, copy_contact, add_wwa, NULL);
  if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
}

/* Helper: copy Contact header value; caller frees. */
static char *get_contact_value(const char *buf, size_t len) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, "Contact", &val, &val_len)) return strdup("");
  char *out = malloc(val_len + 1);
  if (!out) return strdup("");
  memcpy(out, val, val_len);
  out[val_len] = '\0';
  return out;
}

/* Handle REGISTER: parse user, auth, store reg, send 200/401/403. */
static void handle_register(const char *req_buf, size_t req_len, upbx_config *cfg, sip_send_ctx *ctx) {
  log_trace("REGISTER: step entry");
  char h[256], p[32];
  h[0] = p[0] = '\0';
  /* Learn the address the client used to reach us (Request-URI host). Keep both: global for get_advertise_addr fallback; per-extension stored below for Via/Contact when forking to that extension. Do not remove. */
  {
    if (sip_request_uri_host_port(req_buf, req_len, h, sizeof(h), p, sizeof(p)) && h[0] && strcmp(h, "0.0.0.0") != 0) {
      /* Learned from sip:user@host or sip:user@host:port */
    } else {
      /* Fallback: Request-URI may be sip:host or sip:host:port (no @), e.g. REGISTER sip:192.168.69.49;transport=UDP */
      const char *end = req_buf + req_len;
      const char *q = req_buf;
      while (q < end && *q != ' ') q++;
      if (q < end) q++;
      if (q + 4 < end && strncasecmp(q, "sip:", 4) == 0) {
        const char *start = q + 4;
        const char *host_end = start;
        while (host_end < end && *host_end != ';' && *host_end != ' ' && *host_end != '\r' && *host_end != '\n') host_end++;
        if (host_end > start) {
          const char *colon = NULL;
          for (const char *r = start; r < host_end; r++) { if (*r == ':') colon = r; }
          size_t host_len = colon ? (size_t)(colon - start) : (size_t)(host_end - start);
          if (host_len > 0 && host_len < sizeof(h)) {
            memcpy(h, start, host_len);
            h[host_len] = '\0';
            if (colon && colon + 1 < host_end) {
              size_t port_len = (size_t)(host_end - (colon + 1));
              if (port_len < sizeof(p)) { memcpy(p, colon + 1, port_len); p[port_len] = '\0'; }
              else memcpy(p, "5060", 5);
            } else
              memcpy(p, "5060", 5);
          }
        }
      }
    }
    if (h[0] && strcmp(h, "0.0.0.0") != 0) {
      registration_set_advertise_addr(h, p[0] ? p : "5060");
      /* Per-extension learned_host/port are set when we update or create the reg entry below (so forked INVITEs use the address this extension sees us as). */
    }
  }
  char user_buf[256];
  user_buf[0] = '\0';
  const char *user_source = "none";
  if (sip_request_uri_user(req_buf, req_len, user_buf, sizeof(user_buf))) {
    user_source = "Request-URI";
  } else if (sip_header_uri_user(req_buf, req_len, "From", user_buf, sizeof(user_buf))) {
    user_source = "From";
  } else if (sip_header_uri_user(req_buf, req_len, "To", user_buf, sizeof(user_buf))) {
    user_source = "To";
  }
  log_trace("REGISTER: user source=%s, user_buf=\"%s\"", user_source, user_buf[0] ? user_buf : "(empty)");
  char *raw_uri_user = user_buf[0] ? strdup(user_buf) : NULL;  /* original user part (percent-encoded) for digest + stored as reg.uri_user */
  decode_percent_at_inplace(user_buf);  /* RFC 3261: user part may contain @ encoded as %40 */
  const char *user = user_buf;
  if (!user[0]) {
    free(raw_uri_user);
    send_reply(ctx, req_buf, req_len, 400, 0, 0);
    return;
  }
  char *extension_num = NULL;
  const char *at = strchr(user, '@');
  if (at) {
    extension_num = malloc((size_t)(at - user) + 1);
    if (extension_num) {
      memcpy(extension_num, user, (size_t)(at - user));
      extension_num[at - user] = '\0';
    }
  } else
    extension_num = strdup(user);
  if (!extension_num) {
    free(raw_uri_user);
    send_reply(ctx, req_buf, req_len, 503, 0, 0);
    return;
  }
  /* Look up extension from live config (exact ext:<number> then first pattern match). */
  resp_object *ext_section = get_extension_section(extension_num, NULL, 0);
  if (!ext_section) {
    log_warn("REGISTER: 403 Forbidden — extension \"%s\" not in config (username \"%s\")", extension_num, user);
    free(raw_uri_user);
    free(extension_num);
    send_reply(ctx, req_buf, req_len, 403, 0, 0);
    return;
  }
  const char *secret = resp_map_get_string(ext_section, "secret");
  config_trunk *trunk = resolve_trunk_for_extension(cfg, extension_num);
  const char *trunk_name_str = trunk ? trunk->name : "";

  const char *auth_val;
  size_t auth_len;
  int has_auth = sip_header_get(req_buf, req_len, "Authorization", &auth_val, &auth_len);
  log_trace("REGISTER: extension_num=%s trunk=%s has_Authorization=%d", extension_num, trunk_name_str, has_auth ? 1 : 0);

  int plugin_allow = -1;
  if (plugin_count() > 0) {
    log_debug("REGISTER: querying plugins for ext %s on trunk %s", extension_num, trunk_name_str);
    plugin_query_register(extension_num, trunk_name_str, user, &plugin_allow);
  }
  if (plugin_allow == 0) {
    log_info("REGISTER: plugin denied registration for extension %s", extension_num);
    resp_free(ext_section);
    free(raw_uri_user);
    free(extension_num);
    send_reply(ctx, req_buf, req_len, 403, 0, 0);
    return;
  }
  if (plugin_allow != 1) {
    if (!has_auth || !secret) {
      log_debug("REGISTER: 401 challenge for extension %s (no credentials or no secret)", extension_num);
      char *r = build_reply(req_buf, req_len, 401, 0, 1, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      resp_free(ext_section);
      free(raw_uri_user);
      free(extension_num);
      return;
    }
    char *auth_user = NULL, *auth_stripped = NULL;
    if (!sip_parse_authorization_digest(req_buf, req_len, &auth_user, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
      log_debug("REGISTER: 401 challenge for extension %s (invalid Authorization header)", extension_num);
      send_reply(ctx, req_buf, req_len, 401, 0, 1);
      resp_free(ext_section);
      free(raw_uri_user);
      free(extension_num);
      free(auth_user);
      return;
    }
    if (auth_user)
      auth_stripped = extension_part_from_username(auth_user);
    if (!auth_stripped || strcmp(auth_stripped, extension_num) != 0) {
      log_warn("REGISTER: 403 Forbidden — Authorization username \"%s\" does not match extension \"%s\"", auth_stripped ? auth_stripped : "(null)", extension_num);
      resp_free(ext_section);
      free(raw_uri_user);
      free(auth_user); free(auth_stripped); free(extension_num);
      send_reply(ctx, req_buf, req_len, 403, 0, 0);
      return;
    }
    if (!verify_digest(req_buf, req_len, "REGISTER", secret, AUTH_REALM, auth_user)) {
      log_warn("REGISTER: 403 Forbidden — digest verification failed for extension %s", extension_num);
      resp_free(ext_section);
      free(raw_uri_user);
      free(extension_num);
      free(auth_user);
      free(auth_stripped);
      send_reply(ctx, req_buf, req_len, 403, 0, 0);
      return;
    }
    free(auth_user);
    free(auth_stripped);
  }

  log_trace("REGISTER: auth OK, extension=%s", extension_num);
  if (trunk_name_str[0])
    log_info("REGISTER: extension %s registered on trunk %s", extension_num, trunk_name_str);
  else
    log_info("REGISTER: extension %s registered (no trunk)", extension_num);
  char *contact_val = get_contact_value(req_buf, req_len);
  registration_update(extension_num, raw_uri_user, trunk_name_str, contact_val, h, p[0] ? p : "5060", NULL);
  raw_uri_user = NULL;
  resp_free(ext_section);
  send_reply(ctx, req_buf, req_len, 200, 1, 0);
  free(raw_uri_user);
}

static const char *reason_phrase(int code) {
  switch (code) {
    case 100: return "Trying";
    case 180: return "Ringing";
    case 183: return "Session Progress";
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 408: return "Request Timeout";
    case 480: return "Temporarily Unavailable";
    case 486: return "Busy Here";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
  }
}


/* Forward one SIP message (request or response) to dest_addr. */
static void udp_send_to(int sockfd, const struct sockaddr *dest_addr, socklen_t dest_len, const char *buf, size_t len) {
  if (len > 0)
    sendto(sockfd, buf, len, 0, dest_addr, dest_len);
}

/* Build INVITE from existing request buf with new Request-URI (user@host:port). Caller frees. */
static char *build_invite_with_uri(const char *buf, size_t len, const char *user, const char *host, const char *port) {
  char via_buf[512], from_buf[384], to_buf[384], call_id_buf[256], cseq_buf[64], contact_buf[256];
  via_buf[0] = from_buf[0] = to_buf[0] = call_id_buf[0] = cseq_buf[0] = contact_buf[0] = '\0';
  sip_header_copy(buf, len, "Via", via_buf, sizeof(via_buf));
  sip_header_copy(buf, len, "From", from_buf, sizeof(from_buf));
  sip_header_copy(buf, len, "To", to_buf, sizeof(to_buf));
  sip_header_copy(buf, len, "Call-ID", call_id_buf, sizeof(call_id_buf));
  sip_header_copy(buf, len, "CSeq", cseq_buf, sizeof(cseq_buf));
  sip_header_copy(buf, len, "Contact", contact_buf, sizeof(contact_buf));
  const char *body_ptr = NULL;
  size_t body_len = 0;
  sip_request_get_body(buf, len, &body_ptr, &body_len);
  char req_uri[256];
  sip_format_request_uri(user, host, port, req_uri, sizeof(req_uri));
  return sip_build_request_parts("INVITE", req_uri,
    via_buf[0] ? via_buf : NULL, from_buf[0] ? from_buf : NULL, to_buf[0] ? to_buf : NULL,
    call_id_buf[0] ? call_id_buf : NULL, cseq_buf[0] ? cseq_buf : NULL, contact_buf[0] ? contact_buf : NULL,
    0, body_ptr, body_len, NULL);
}

/* Get CSeq number from request (first token of CSeq header). */
static int get_cseq_number(const char *buf, size_t len) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, "CSeq", &val, &val_len) || val_len == 0) return 0;
  return atoi(val);
}

/* Send CANCEL to all FORK_ACTIVE forks of a call. Marks them FORK_DONE.
 * Uses call->original_invite for From/To/CSeq. */
static void cancel_active_forks(call_t *call, int sockfd) {
  if (!call || !call->original_invite || call->original_invite_len == 0) return;
  log_trace("cancel_active_forks: call=%.32s, %zu forks", call->call_id, call->n_forks);
  const char *inv = call->original_invite;
  size_t inv_len = call->original_invite_len;
  char from_buf[384], to_buf[384], cseq_buf[64];
  from_buf[0] = to_buf[0] = '\0';
  sip_header_copy(inv, inv_len, "From", from_buf, sizeof(from_buf));
  sip_header_copy(inv, inv_len, "To", to_buf, sizeof(to_buf));
  int cseq_num = get_cseq_number(inv, inv_len);

  for (size_t f = 0; f < call->n_forks; f++) {
    if (call->fork_state[f] != FORK_ACTIVE) continue;
    const char *via_val = call->fork_vias[f];
    if (!via_val) continue;
    char cancel_uri[256];
    if (fork_uri_from_addr(&call->fork_addrs[f], call->fork_ids[f], cancel_uri, sizeof(cancel_uri)) != 0) continue;
    snprintf(cseq_buf, sizeof(cseq_buf), "%d CANCEL", cseq_num);
    char *cancel = sip_build_request_parts("CANCEL", cancel_uri,
      via_val, from_buf[0] ? from_buf : NULL, to_buf[0] ? to_buf : NULL,
      call->call_id, cseq_buf, NULL, 0, NULL, 0, NULL);
    if (cancel) {
      udp_send_to(sockfd, (struct sockaddr *)&call->fork_addrs[f], call->fork_lens[f], cancel, strlen(cancel));
      free(cancel);
    }
    call->fork_state[f] = FORK_DONE;
  }
}

static int parse_listen_addr(const char *addr, char *host, size_t host_size, char *port, size_t port_size);
static int get_advertise_addr(upbx_config *cfg, char *host_out, size_t host_size, char *port_out, size_t port_size);
static int get_advertise_addr_for_ext(upbx_config *cfg, const ext_reg_t *reg, char *host_out, size_t host_size, char *port_out, size_t port_size);
static int send_fork_invite_to_ext(call_t *call, upbx_config *cfg, ext_reg_t *ext, const char *source_str, int sockfd);

/* Apply overflow action for one call (busy/redirect/include). Single-threaded. Uses live config. */
static void overflow_apply_one(call_t *call, upbx_config *cfg, int sockfd) {
  if (!call || !call->trunk_name) return;
  if (call->answered || call->overflow_done) return;
  log_trace("overflow_apply_one: call=%.32s", call->call_id);
  char section[128];
  snprintf(section, sizeof(section), "trunk:%s", call->trunk_name);
  resp_object *to_obj = config_key_get(section, "overflow_timeout");
  int timeout_sec = (to_obj && to_obj->type == RESPT_INT) ? (int)to_obj->u.i : 0;
  if (to_obj) resp_free(to_obj);
  if (timeout_sec <= 0) return;
  time_t deadline = call->created_at + (time_t)timeout_sec;
  if (time(NULL) < deadline) return;
  call->overflow_done = 1;
  resp_object *strat_obj = config_key_get(section, "overflow_strategy");
  resp_object *tgt_obj = config_key_get(section, "overflow_target");
  const char *strategy = (strat_obj && (strat_obj->type == RESPT_BULK || strat_obj->type == RESPT_SIMPLE) && strat_obj->u.s) ? strat_obj->u.s : "none";
  const char *target = (tgt_obj && (tgt_obj->type == RESPT_BULK || tgt_obj->type == RESPT_SIMPLE)) ? tgt_obj->u.s : NULL;
  log_debug("overflow: call %.32s strategy=%s target=%s", call->call_id, strategy, target ? target : "(none)");
  int do_busy = 0, do_include = 0, do_redirect = 0;
  if (strcasecmp(strategy, "busy") == 0) do_busy = 1;
  else if (strcasecmp(strategy, "include") == 0 && target && target[0]) do_include = 1;
  else if (strcasecmp(strategy, "redirect") == 0 && target && target[0]) do_redirect = 1;
  if (strat_obj) resp_free(strat_obj);
  if (tgt_obj) resp_free(tgt_obj);

  if (do_busy) {
    if (call->original_invite && call->original_invite_len > 0) {
      char *resp = build_reply(call->original_invite, call->original_invite_len, 486, 0, 0, NULL);
      if (resp) {
        udp_send_to(sockfd, (struct sockaddr *)&call->a.sip_addr, call->a.sip_len, resp, strlen(resp));
        free(resp);
      }
    }
    call_remove(call);
    return;
  }

  resp_object *tgt2 = config_key_get(section, "overflow_target");
  const char *overflow_target = (tgt2 && (tgt2->type == RESPT_BULK || tgt2->type == RESPT_SIMPLE) && tgt2->u.s) ? tgt2->u.s : NULL;
  if (do_redirect) {
    cancel_active_forks(call, sockfd);
    clear_pending_exts(call);
    if (overflow_target && overflow_target[0] && call->n_pending_exts < CALL_MAX_FORKS)
      call->pending_exts[call->n_pending_exts++] = strdup(overflow_target);
  } else if (do_include) {
    if (overflow_target && overflow_target[0] && call->n_pending_exts < CALL_MAX_FORKS)
      call->pending_exts[call->n_pending_exts++] = strdup(overflow_target);
  }
  if (tgt2) resp_free(tgt2);
}

/* Return 1 if the given extension has any answered (active) call, excluding 'exclude'. */
static int extension_has_active_call(const char *ext_number, const call_t *exclude) {
  if (!ext_number || !ext_number[0]) return 0;
  for (call_t *c = call_first(); c; c = c->next) {
    if (c == exclude) continue;
    if (!c->answered) continue;
    if ((c->a.id && strcmp(c->a.id, ext_number) == 0) ||
        (c->b.id && strcmp(c->b.id, ext_number) == 0))
      return 1;
  }
  return 0;
}

/* Protothread: pending extension handler + overflow timer.
 * The pending handler runs every iteration (sub-millisecond latency).
 * The overflow timer runs every ~1s. */
static struct pt pt_overflow;
static time_t overflow_last_run;

static PT_THREAD(overflow_pt(struct pt *pt, upbx_config *cfg, int sockfd)) {
  PT_BEGIN(pt);
  overflow_last_run = 0;
  for (;;) {
    /* Pending extension handler (runs every iteration) */
    for (call_t *c = call_first(); c; ) {
      call_t *next = c->next;
      if (!c->answered && !c->cancelling && c->n_pending_exts > 0) {
        for (size_t p = 0; p < c->n_pending_exts; ) {
          if (!extension_has_active_call(c->pending_exts[p], c)) {
            /* Extension is free — look up registration and send INVITE. */
            ext_reg_t *reg = NULL;
            if (c->trunk_name && c->trunk_name[0]) {
              reg = registration_get_by_number(c->trunk_name, c->pending_exts[p]);
            } else {
              /* Ext-to-ext: no trunk context, find any registration for this number. */
              ext_reg_t **regs = NULL;
              size_t nregs = registration_get_regs(NULL, c->pending_exts[p], &regs);
              if (nregs > 0 && regs) reg = regs[0];
              free(regs);
            }
            if (reg) {
              send_fork_invite_to_ext(c, cfg, reg, c->source_str, c->sockfd);
            } else {
              log_debug("INVITE pending: ext %s not registered, dropping from pending", c->pending_exts[p]);
            }
            /* Remove from pending list (swap-and-shrink). */
            free(c->pending_exts[p]);
            c->pending_exts[p] = c->pending_exts[c->n_pending_exts - 1];
            c->n_pending_exts--;
          } else {
            p++;
          }
        }
      }
      c = next;
    }

    /* Overflow timer (runs every ~1s) */
    {
      time_t now = time(NULL);
      if (now - overflow_last_run >= 1) {
        overflow_last_run = now;
        for (call_t *c = call_first(); c; ) {
          call_t *next = c->next;
          overflow_apply_one(c, cfg, sockfd);
          c = next;
        }
      }
    }
    PT_YIELD(pt);
  }
  PT_END(pt);
}

/* Send a forked INVITE to a single extension registration.
 * Uses call->original_invite as the source INVITE.
 * Resolves the extension's contact, builds and rewrites the INVITE,
 * sends it, and records the fork in call->fork_addrs/ids/vias/state.
 * Returns 0 on success, -1 on failure (skip). */
static int send_fork_invite_to_ext(call_t *call, upbx_config *cfg,
    ext_reg_t *ext, const char *source_str, int sockfd) {
  log_trace("send_fork_invite_to_ext: ext=%s call=%.32s", ext ? (ext->number ? ext->number : "?") : "null", call ? call->call_id : "");
  if (!call || !call->original_invite || call->original_invite_len == 0) return -1;
  if (!ext || !ext->contact) return -1;
  if (call->n_forks >= CALL_MAX_FORKS) return -1;

  const char *req_buf = call->original_invite;
  size_t req_len = call->original_invite_len;

  char host[256], port[32];
  if (contact_to_host_port(ext->contact, host, sizeof(host), port, sizeof(port)) != 0) {
    log_warn("INVITE fork: skip %s, bad contact", ext->number ? ext->number : "?");
    return -1;
  }
  char via_host[256], via_port[32];
  if (get_advertise_addr_for_ext(cfg, ext, via_host, sizeof(via_host), via_port, sizeof(via_port)) != 0) {
    log_warn("INVITE fork: skip %s, no advertise addr", ext->number ? ext->number : "?");
    return -1;
  }
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
    log_warn("INVITE fork: skip %s, getaddrinfo failed for %s:%s", ext->number ? ext->number : "?", host, port);
    return -1;
  }

  /* Build Request-URI for this callee. */
  char req_uri[256];
  const char *ru_user = (ext->uri_user && ext->uri_user[0]) ? ext->uri_user : ext->number;
  sip_format_request_uri(ru_user ? ru_user : "", host, port, req_uri, sizeof(req_uri));

  /* Build Contact pointing to PBX. */
  char contact_val[256];
  sip_format_contact_uri_value(source_str ? source_str : "", via_host, via_port, contact_val, sizeof(contact_val));

  /* Build To value: use the callee's original registered URI so its client recognises the call. */
  char to_val[384];
  to_val[0] = '\0';
  {
    const char *to_user = (ext->uri_user && ext->uri_user[0]) ? ext->uri_user : ext->number;
    sip_format_contact_uri_value(to_user ? to_user : "", via_host, via_port, to_val, sizeof(to_val));
    /* Preserve original To tag if any. */
    char to_tag[64];
    to_tag[0] = '\0';
    if (sip_header_get_param(req_buf, req_len, "To", "tag", to_tag, sizeof(to_tag)) && to_tag[0])
      sip_append_tag_param(to_val, sizeof(to_val), to_tag);
  }

  /* Build Via value for this leg. */
  char via_val[256];
  sip_make_via_line(via_host, via_port, via_val, sizeof(via_val));

  /* Build From value: only rewrite when caller is an exact local extension.
   * Pattern-matched callers (e.g. downstream PBX via trunk-server) keep their
   * original From header to preserve caller identity pass-through. */
  char from_val[384];
  from_val[0] = '\0';
  if (source_str) {
    resp_object *ext_caller_sec = get_extension_section(source_str, NULL, 0);
    if (ext_caller_sec) {
      const char *caller_display = resp_map_get_string(ext_caller_sec, "name");
      sip_format_from_to_value((caller_display && caller_display[0]) ? caller_display : NULL, source_str, via_host, via_port, from_val, sizeof(from_val));
      char tag_buf[64];
      tag_buf[0] = '\0';
      if (sip_header_get_param(req_buf, req_len, "From", "tag", tag_buf, sizeof(tag_buf)) && tag_buf[0])
        sip_append_tag_param(from_val, sizeof(from_val), tag_buf);
      resp_free(ext_caller_sec);
    }
  }

  /* Chain rewrites on the original INVITE: URI → Via → Contact → From → SDP → body. */
  char tmp1[SIP_READ_BUF_SIZE], tmp2[SIP_READ_BUF_SIZE], tmp3[SIP_READ_BUF_SIZE];
  int cur_len;

  cur_len = sip_rewrite_request_uri(req_buf, req_len, req_uri, tmp1, sizeof(tmp1));
  if (cur_len < 0) { freeaddrinfo(res); return -1; }

  cur_len = sip_prepend_via(tmp1, (size_t)cur_len, via_val, tmp2, sizeof(tmp2));
  if (cur_len < 0) { freeaddrinfo(res); return -1; }

  cur_len = sip_rewrite_header(tmp2, (size_t)cur_len, "Contact", contact_val, tmp3, sizeof(tmp3));
  if (cur_len < 0) { freeaddrinfo(res); return -1; }

  if (to_val[0]) {
    cur_len = sip_rewrite_header(tmp3, (size_t)cur_len, "To", to_val, tmp1, sizeof(tmp1));
    if (cur_len > 0) { memcpy(tmp3, tmp1, (size_t)cur_len); }
  }

  if (from_val[0]) {
    cur_len = sip_rewrite_header(tmp3, (size_t)cur_len, "From", from_val, tmp1, sizeof(tmp1));
    if (cur_len > 0) { memcpy(tmp3, tmp1, (size_t)cur_len); }
  }

  /* Insert Alert-Info so callee UA rings audibly. */
  {
    int ai_len = sip_insert_header(tmp3, (size_t)cur_len, "Alert-Info",
                                   "<http://127.0.0.1/bellcore-dr1>", tmp1, sizeof(tmp1));
    if (ai_len > 0) { memcpy(tmp3, tmp1, (size_t)ai_len); cur_len = ai_len; }
  }

  /* Rewrite SDP body (c= IP and m= port) if present. */
  {
    const char *cur_body;
    size_t cur_body_len;
    if (call->rtp_port_b > 0 &&
        sip_request_get_body(tmp3, (size_t)cur_len, &cur_body, &cur_body_len) && cur_body_len > 0) {
      char new_sdp[4096];
      int sdp_len = sdp_rewrite_addr(cur_body, cur_body_len, via_host, call->rtp_port_b, new_sdp, sizeof(new_sdp));
      if (sdp_len > 0) {
        int new_len = sip_rewrite_body(tmp3, (size_t)cur_len, new_sdp, (size_t)sdp_len, tmp1, sizeof(tmp1));
        if (new_len >= 0) { memcpy(tmp3, tmp1, (size_t)new_len); cur_len = new_len; }
      }
    }
  }

  log_debug("INVITE fork: sending to %s at %s:%s call=%.32s", ext->number ? ext->number : "?", host, port, call->call_id);
  log_hexdump_trace(tmp3, (size_t)cur_len);
  udp_send_to(sockfd, res->ai_addr, res->ai_addrlen, tmp3, (size_t)cur_len);

  /* Record fork. */
  size_t f = call->n_forks;
  memcpy(&call->fork_addrs[f], res->ai_addr, res->ai_addrlen);
  call->fork_lens[f] = res->ai_addrlen;
  call->fork_ids[f]  = ext->number ? strdup(ext->number) : NULL;
  call->fork_vias[f] = strdup(via_val);
  call->fork_state[f] = FORK_ACTIVE;
  call->n_forks++;

  freeaddrinfo(res);
  return 0;
}

/* Fork INVITE to a list of extension registrations.
 * Creates call_t, allocates RTP ports, stores original INVITE, and adds all
 * target extension numbers to pending_exts. The pending handler in overflow_pt
 * will send the actual INVITEs on the next main-loop iteration.
 * trunk may be NULL (ext-to-ext). direction is "dialin" or "dialout". Caller frees exts. */
static void fork_invite_to_extension_regs(upbx_config *cfg, const char *req_buf, size_t req_len, sip_send_ctx *ctx,
  ext_reg_t **exts, size_t n_ext, config_trunk *trunk, const char *source_str, const char *direction) {
  log_trace("fork_invite_to_extension_regs: entry, %zu extension(s)", n_ext);

  /* Extract Call-ID. */
  char call_id_buf[CALL_ID_MAX];
  call_id_buf[0] = '\0';
  sip_header_copy(req_buf, req_len, "Call-ID", call_id_buf, sizeof(call_id_buf));

  /* Create call_t. */
  call_t *call = call_create(call_id_buf);
  if (!call) {
    send_reply(ctx, req_buf, req_len, 503, 0, 0);
    return;
  }
  call->sockfd = ctx->sockfd;
  call->trunk_name = trunk && trunk->name ? strdup(trunk->name) : NULL;
  call->direction = strdup(direction ? direction : "dialin");
  call->source_str = source_str ? strdup(source_str) : NULL;
  memcpy(&call->a.sip_addr, &ctx->peer, sizeof(ctx->peer));
  call->a.sip_len = ctx->peerlen;
  call->a.id = source_str ? strdup(source_str) : NULL;

  /* Store original INVITE for fork sending and ACK/BYE forwarding. */
  call->original_invite = malloc(req_len + 1);
  if (call->original_invite) {
    memcpy(call->original_invite, req_buf, req_len);
    call->original_invite[req_len] = '\0';
    call->original_invite_len = req_len;
  }

  /* Store caller's Via for stripping on responses. */
  {
    char via_buf[512];
    via_buf[0] = '\0';
    sip_header_copy(req_buf, req_len, "Via", via_buf, sizeof(via_buf));
    call->caller_via = via_buf[0] ? strdup(via_buf) : NULL;
  }

  if (!(trunk && trunk->overflow_timeout > 0 && trunk->overflow_strategy && trunk->overflow_strategy[0] &&
      strcasecmp(trunk->overflow_strategy, "none") != 0)) {
    call->overflow_done = 1;
  }

  /* Parse caller SDP to learn remote RTP address (party A). */
  const char *body;
  size_t body_len;
  sdp_media_t sdp_media[SDP_MAX_MEDIA];
  size_t sdp_n = 0;
  if (sip_request_get_body(req_buf, req_len, &body, &body_len) && body_len > 0)
    sdp_parse_media(body, body_len, sdp_media, SDP_MAX_MEDIA, &sdp_n);

  if (sdp_n > 0 && sdp_media[0].port > 0) {
    inet_aton(sdp_media[0].ip, &call->rtp_remote_a.sin_addr);
    call->rtp_remote_a.sin_family = AF_INET;
    call->rtp_remote_a.sin_port   = htons((uint16_t)sdp_media[0].port);
  }

  /* Allocate RTP port pair: one facing caller (A), one facing callee (B). */
  struct in_addr bind_any;
  bind_any.s_addr = INADDR_ANY;
  if (call_rtp_alloc_port(bind_any, cfg->rtp_port_low, cfg->rtp_port_high,
                          &call->rtp_sock_a, &call->rtp_port_a) != 0)
    log_error("RTP: failed to allocate port for party A, call %.32s", call_id_buf);
  if (call_rtp_alloc_port(bind_any, cfg->rtp_port_low, cfg->rtp_port_high,
                          &call->rtp_sock_b, &call->rtp_port_b) != 0)
    log_error("RTP: failed to allocate port for party B, call %.32s", call_id_buf);

  log_debug("RTP: relay ports A=%d B=%d for call %.32s",
           call->rtp_port_a, call->rtp_port_b, call_id_buf);

  /* Add all target extensions to pending_exts. The pending handler in
   * overflow_pt will send the actual INVITEs on the next main-loop iteration. */
  for (size_t i = 0; i < n_ext && call->n_pending_exts < CALL_MAX_FORKS; i++) {
    if (exts[i]->number)
      call->pending_exts[call->n_pending_exts++] = strdup(exts[i]->number);
  }

  /* Send 100 Trying to caller. */
  send_reply(ctx, req_buf, req_len, 100, 0, 0);
}

/* Incoming INVITE: DID matches trunk → fork to extensions. If override_ext_numbers non-NULL, ring only those (on this trunk). */
static void handle_invite_incoming(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx, const char *did,
  const char **override_ext_numbers, size_t n_override) {
  log_trace("handle_invite_incoming: DID=%s overrides=%zu", did ? did : "", n_override);
  config_trunk *trunk = find_trunk_by_did(cfg, did);
  if (!trunk) {
    send_reply(ctx, buf, len, 404, 0, 0);
    return;
  }
  ext_reg_t **exts = NULL;
  size_t n_ext = 0;
  if (override_ext_numbers && n_override > 0) {
    exts = (ext_reg_t **)malloc(n_override * sizeof(ext_reg_t *));
    if (exts) {
      for (size_t k = 0; k < n_override; k++) {
        ext_reg_t *r = registration_get_by_number(trunk->name, override_ext_numbers[k]);
        if (r) exts[n_ext++] = r;
      }
      if (n_ext == 0) { free(exts); exts = NULL; }
    }
  } else
    n_ext = get_group_regs(cfg, trunk, &exts);
  if (n_ext == 0 || !exts) {
    free(exts);
    send_reply(ctx, buf, len, 480, 0, 0);
    return;
  }
  fork_invite_to_extension_regs(cfg, buf, len, ctx, exts, n_ext, trunk, did, "dialin");
  free(exts);
}

/* Outgoing INVITE: from registered extension → forward to extension's trunk group (with fallback and CID).
 * n_trunk_override == -1: no override, use group order. n_trunk_override >= 0: use trunk_override list (0 = empty → no trunks). */
static void handle_invite_outgoing(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx, const char *from_user,
  const char **trunk_override, int n_trunk_override) {
  log_trace("handle_invite_outgoing: from=%s", from_user ? from_user : "");
  const char *at = strchr(from_user, '@');
  size_t ext_len = at ? (size_t)(at - from_user) : strlen(from_user);
  char *ext_num = malloc(ext_len + 1);
  if (!ext_num) {
    send_reply(ctx, buf, len, 503, 0, 0);
    return;
  }
  memcpy(ext_num, from_user, ext_len);
  ext_num[ext_len] = '\0';
  ext_reg_t **ext_matches = NULL;
  size_t ext_match_count = registration_get_regs(NULL, ext_num, &ext_matches);
  ext_reg_t *reg = ext_match_count > 0 ? ext_matches[0] : NULL;
  free(ext_matches);
  if (!reg) {
    char pat_sec[128];
    resp_object *pat_sec_obj = get_extension_section(ext_num, pat_sec, sizeof(pat_sec));
    if (pat_sec_obj) {
      const char *section_tail = (strlen(pat_sec) > 4) ? pat_sec + 4 : "";
      resp_free(pat_sec_obj);
      if (section_tail[0] && strcmp(section_tail, ext_num) != 0) {
        ext_matches = NULL;
        ext_match_count = registration_get_regs(NULL, section_tail, &ext_matches);
        reg = ext_match_count > 0 ? ext_matches[0] : NULL;
        free(ext_matches);
      }
    }
  }
  /* Find primary trunk: try registration first, then fall back to prefix-based resolution. */
  config_trunk *primary_trunk = NULL;
  if (reg && reg->trunk_name && reg->trunk_name[0])
    primary_trunk = get_trunk_config(cfg, reg->trunk_name);
  if (!primary_trunk)
    primary_trunk = resolve_trunk_for_extension(cfg, ext_num);
  free(ext_num);
  if (!reg && !primary_trunk) {
    send_reply(ctx, buf, len, 404, 0, 0);
    return;
  }
  if (!primary_trunk) {
    /* Trunk-less extension trying to call externally → no trunk available. */
    log_info("INVITE outgoing: ext %s has no trunk, rejecting external call", from_user);
    send_reply(ctx, buf, len, 503, 0, 0);
    return;
  }

  /* Build trunk list: from plugin override (by name) or from group. */
  config_trunk *group_trunks[64];
  size_t n_group = 0;
  if (n_trunk_override >= 0 && trunk_override) {
    for (int i = 0; i < n_trunk_override && n_group < 64; i++) {
      config_trunk *t = get_trunk_config(cfg, trunk_override[i]);
      if (t) group_trunks[n_group++] = t;
    }
  }
  if (n_trunk_override < 0)
    n_group = get_group_trunks(cfg, primary_trunk, group_trunks, 64);
  if (n_group == 0) {
    send_reply(ctx, buf, len, 503, 0, 0);
    return;
  }
  config_trunk *trunk = NULL;
  for (size_t i = 0; i < n_group; i++) {
    if (group_trunks[i]->host && group_trunks[i]->host[0] &&
        trunk_reg_is_available(group_trunks[i]->name)) {
      trunk = group_trunks[i];
      break;
    }
  }
  if (!trunk) {
    /* No available trunk: graceful degradation to first in group with a host. */
    for (size_t i = 0; i < n_group; i++) {
      if (group_trunks[i]->host && group_trunks[i]->host[0]) { trunk = group_trunks[i]; break; }
    }
  }
  if (!trunk || !trunk->host) {
    send_reply(ctx, buf, len, 503, 0, 0);
    return;
  }
  log_debug("outgoing: selected trunk %s for ext %s (group %zu trunk(s))", trunk->name, from_user, n_group);

  /* Start with possibly rewritten INVITE (trunk number patterns). */
  const char *send_buf = buf;
  size_t send_len = len;
  char *rewritten_buf = NULL;
  if (trunk->rewrite_regex && trunk->rewrite_count > 0) {
    char req_user[256], req_host[256], req_port[32];
    if (sip_request_uri_user(buf, len, req_user, sizeof(req_user)) &&
        sip_request_uri_host_port(buf, len, req_host, sizeof(req_host), req_port, sizeof(req_port))) {
      char rewritten[256];
      apply_trunk_rewrites(trunk, req_user, rewritten, sizeof(rewritten));
      rewritten_buf = build_invite_with_uri(buf, len, rewritten, req_host, req_port);
      if (rewritten_buf) { send_buf = rewritten_buf; send_len = strlen(rewritten_buf); }
    }
  }

  const char *port = (trunk->port && trunk->port[0]) ? trunk->port : "5060";
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(trunk->host, port, &hints, &res) != 0 || !res) {
    free(rewritten_buf);
    send_reply(ctx, buf, len, 503, 0, 0);
    return;
  }

  /* Create call_t for response matching and RTP relay. */
  char call_id_buf[CALL_ID_MAX];
  call_id_buf[0] = '\0';
  sip_header_copy(buf, len, "Call-ID", call_id_buf, sizeof(call_id_buf));

  call_t *call = call_create(call_id_buf);
  if (call) {
    call->sockfd = ctx->sockfd;
    call->trunk_name = trunk && trunk->name ? strdup(trunk->name) : NULL;
    call->direction = strdup("dialout");
    call->source_str = from_user ? strdup(from_user) : NULL;
    memcpy(&call->a.sip_addr, &ctx->peer, sizeof(ctx->peer));
    call->a.sip_len = ctx->peerlen;
    call->a.id = from_user ? strdup(from_user) : NULL;

    /* Store original INVITE. */
    call->original_invite = malloc(len + 1);
    if (call->original_invite) {
      memcpy(call->original_invite, buf, len);
      call->original_invite[len] = '\0';
      call->original_invite_len = len;
    }
    { char via_buf[512]; via_buf[0] = '\0';
      sip_header_copy(buf, len, "Via", via_buf, sizeof(via_buf));
      call->caller_via = via_buf[0] ? strdup(via_buf) : NULL; }
    call->overflow_done = 1; /* no overflow for outgoing */

    /* Allocate RTP relay ports. */
    struct in_addr bind_any;
    bind_any.s_addr = INADDR_ANY;
    call_rtp_alloc_port(bind_any, cfg->rtp_port_low, cfg->rtp_port_high,
                        &call->rtp_sock_a, &call->rtp_port_a);
    call_rtp_alloc_port(bind_any, cfg->rtp_port_low, cfg->rtp_port_high,
                        &call->rtp_sock_b, &call->rtp_port_b);

    /* Parse caller SDP for party A RTP address. */
    const char *body;
    size_t body_len;
    sdp_media_t sdp_media[SDP_MAX_MEDIA];
    size_t sdp_n = 0;
    if (sip_request_get_body(send_buf, send_len, &body, &body_len) && body_len > 0)
      sdp_parse_media(body, body_len, sdp_media, SDP_MAX_MEDIA, &sdp_n);
    if (sdp_n > 0 && sdp_media[0].port > 0) {
      inet_aton(sdp_media[0].ip, &call->rtp_remote_a.sin_addr);
      call->rtp_remote_a.sin_family = AF_INET;
      call->rtp_remote_a.sin_port   = htons((uint16_t)sdp_media[0].port);
    }

    /* Rewrite INVITE: prepend Via + rewrite SDP + apply trunk CID. */
    char via_host[256], via_port_s[32];
    if (get_advertise_addr(cfg, via_host, sizeof(via_host), via_port_s, sizeof(via_port_s)) == 0) {
      char via_val[256];
      sip_make_via_line(via_host, via_port_s, via_val, sizeof(via_val));

      /* Record trunk as fork target (with Via for CANCEL). */
      if (call->n_forks < CALL_MAX_FORKS) {
        memcpy(&call->fork_addrs[0], res->ai_addr, res->ai_addrlen);
        call->fork_lens[0] = res->ai_addrlen;
        call->fork_ids[0]  = trunk->name ? strdup(trunk->name) : NULL;
        call->fork_vias[0] = strdup(via_val);
        call->n_forks = 1;
      }
      char t1[SIP_READ_BUF_SIZE], t2[SIP_READ_BUF_SIZE];
      int cur_len = sip_prepend_via(send_buf, send_len, via_val, t1, sizeof(t1));

      /* Apply trunk CID to From header if configured. */
      if (cur_len > 0 && ((trunk->cid && trunk->cid[0]) || (trunk->cid_name && trunk->cid_name[0]))) {
        const char *cid_num = (trunk->cid && trunk->cid[0]) ? trunk->cid : from_user;
        const char *cid_display = (trunk->cid_name && trunk->cid_name[0]) ? trunk->cid_name : NULL;
        char from_val[384];
        sip_format_from_to_value(cid_display, cid_num, via_host, via_port_s, from_val, sizeof(from_val));
        /* Preserve original From tag. */
        char tag_buf[64];
        tag_buf[0] = '\0';
        if (sip_header_get_param(t1, (size_t)cur_len, "From", "tag", tag_buf, sizeof(tag_buf)) && tag_buf[0])
          sip_append_tag_param(from_val, sizeof(from_val), tag_buf);
        int rw_len = sip_rewrite_header(t1, (size_t)cur_len, "From", from_val, t2, sizeof(t2));
        if (rw_len > 0) { memcpy(t1, t2, (size_t)rw_len); cur_len = rw_len; }
      }

      if (cur_len > 0 && call->rtp_port_b > 0 && sdp_n > 0) {
        const char *sb;
        size_t sbl;
        if (sip_request_get_body(t1, (size_t)cur_len, &sb, &sbl) && sbl > 0) {
          char new_sdp[4096];
          int sdp_len = sdp_rewrite_addr(sb, sbl, via_host, call->rtp_port_b, new_sdp, sizeof(new_sdp));
          if (sdp_len > 0) {
            int new_len = sip_rewrite_body(t1, (size_t)cur_len, new_sdp, (size_t)sdp_len, t2, sizeof(t2));
            if (new_len > 0) { memcpy(t1, t2, (size_t)new_len); cur_len = new_len; }
          }
        }
      }
      if (cur_len > 0) {
        log_trace("sip_server: sending %d bytes to trunk %s (%s:%s)", cur_len, trunk->name, trunk->host, port);
        log_hexdump_trace(t1, (size_t)cur_len);
        udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, t1, (size_t)cur_len);
      } else {
        udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, send_buf, send_len);
      }
    } else {
      udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, send_buf, send_len);
    }
  } else {
    udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, send_buf, send_len);
  }

  free(rewritten_buf);
  freeaddrinfo(res);
  send_reply(ctx, buf, len, 100, 0, 0);
}

/* Dispatch INVITE: call.dialin / call.dialout plugin events, then incoming (DID) or outgoing (from extension). */
static void handle_invite(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx) {
  log_trace("handle_invite: entry");
  char to_user_buf[256], from_user_buf[256], call_id_buf[256];
  to_user_buf[0] = from_user_buf[0] = call_id_buf[0] = '\0';
  sip_request_uri_user(buf, len, to_user_buf, sizeof(to_user_buf));
  if (!to_user_buf[0]) sip_header_uri_user(buf, len, "To", to_user_buf, sizeof(to_user_buf));
  sip_header_uri_user(buf, len, "From", from_user_buf, sizeof(from_user_buf));
  decode_percent_at_inplace(to_user_buf);
  decode_percent_at_inplace(from_user_buf);
  /* Extension number = part before @ (for config lookup). */
  char from_ext_buf[64], to_ext_buf[64];
  const char *from_ext = from_user_buf;
  const char *to_ext = to_user_buf;
  {
    const char *at = strchr(from_user_buf, '@');
    if (at && (size_t)(at - from_user_buf) < sizeof(from_ext_buf)) {
      size_t n = (size_t)(at - from_user_buf);
      memcpy(from_ext_buf, from_user_buf, n);
      from_ext_buf[n] = '\0';
      from_ext = from_ext_buf;
    }
  }
  {
    const char *at = strchr(to_user_buf, '@');
    if (at && (size_t)(at - to_user_buf) < sizeof(to_ext_buf)) {
      size_t n = (size_t)(at - to_user_buf);
      memcpy(to_ext_buf, to_user_buf, n);
      to_ext_buf[n] = '\0';
      to_ext = to_ext_buf;
    }
  }
  const char *call_id_val;
  size_t call_id_len;
  if (sip_header_get(buf, len, "Call-ID", &call_id_val, &call_id_len) && call_id_len < sizeof(call_id_buf)) {
    memcpy(call_id_buf, call_id_val, call_id_len);
    call_id_buf[call_id_len] = '\0';
  }
  const char *to_user = to_user_buf;
  const char *from_user = from_user_buf;
  const char *call_id = call_id_buf;
  log_trace("handle_invite: To=%s From=%s Call-ID=%.32s", to_user[0] ? to_user : "(null)", from_user[0] ? from_user : "(null)", call_id);

  /* 1. From a known extension */
  int from_ext_configured = 0;
  if (from_ext[0]) {
    resp_object *s = get_extension_section(from_ext, NULL, 0);
    if (s) { from_ext_configured = 1; resp_free(s); }
  }
  if (from_ext_configured) {
    char *ext_num = strdup(from_ext);
    if (!ext_num) {
      send_reply(ctx, buf, len, 503, 0, 0);
      return;
    }

    /* 1-pre. Emergency number bypass: skip short-dialing and ext-to-ext, route externally. */
    if (is_emergency_number(cfg, to_ext)) {
      log_info("new call: ext %s -> emergency %s (bypass)", ext_num, to_ext);
      free(ext_num);
      handle_invite_outgoing(cfg, buf, len, ctx, from_user, NULL, -1);
      return;
    }

    /* 1-pre2. Short-dialing expansion: when locality > 0 and dialed number has exactly 'locality' digits,
     * prepend caller's group prefix to form a full number. */
    char expanded_to_ext[128];
    expanded_to_ext[0] = '\0';
    if (cfg->locality > 0 && to_ext[0] && (int)strlen(to_ext) == cfg->locality) {
      config_trunk *caller_trunk = resolve_trunk_for_extension(cfg, from_ext);
      if (caller_trunk && caller_trunk->group_prefix && caller_trunk->group_prefix[0]) {
        snprintf(expanded_to_ext, sizeof(expanded_to_ext), "%s%s", caller_trunk->group_prefix, to_ext);
        {
          resp_object *xs = get_extension_section(expanded_to_ext, NULL, 0);
          if (xs) {
            resp_free(xs);
            log_debug("short-dial: %s expanded to %s (prefix %s)", to_ext, expanded_to_ext, caller_trunk->group_prefix);
            to_ext = expanded_to_ext;
          } else {
            expanded_to_ext[0] = '\0';
          }
        }
      }
    }

    /* 1a. Extension-to-extension: callee is a known extension (exact or pattern). */
    resp_object *callee_ext_sec = (to_ext[0] && strcmp(ext_num, to_ext) != 0) ? get_extension_section(to_ext, NULL, 0) : NULL;
    if (callee_ext_sec) {
      if (cfg->locality > 0 && !cfg->cross_group_calls) {
        config_trunk *caller_trunk = resolve_trunk_for_extension(cfg, from_ext);
        config_trunk *callee_trunk = resolve_trunk_for_extension(cfg, to_ext);
        const char *caller_prefix = caller_trunk ? caller_trunk->group_prefix : NULL;
        const char *callee_prefix = callee_trunk ? callee_trunk->group_prefix : NULL;
        int same_group = 0;
        if (!caller_prefix && !callee_prefix) same_group = 1;
        else if (caller_prefix && callee_prefix && strcmp(caller_prefix, callee_prefix) == 0) same_group = 1;
        if (!same_group) {
          log_info("INVITE: cross-group ext-to-ext blocked %s -> %s", ext_num, to_ext);
          resp_free(callee_ext_sec);
          free(ext_num);
          send_reply(ctx, buf, len, 403, 0, 0);
          return;
        }
      }
      ext_reg_t **exts = NULL;
      size_t n_ext = registration_get_regs(NULL, to_ext, &exts);
      if (n_ext > 0 && exts) {
        log_info("new call: ext %s -> ext %s (ext-to-ext, %zu reg(s))", ext_num, to_ext, n_ext);
        fork_invite_to_extension_regs(cfg, buf, len, ctx, exts, n_ext, NULL, ext_num, "dialin");
        free(exts);
        resp_free(callee_ext_sec);
        free(ext_num);
        return;
      }
      log_debug("INVITE %s->%s: no registration for callee, sending 480", ext_num, to_ext);
      resp_free(callee_ext_sec);
      send_reply(ctx, buf, len, 480, 0, 0);
      free(exts);
      free(ext_num);
      return;
    }

    /* 1b. call.dialout plugin event — always fires for outgoing calls from extensions. */
    ext_reg_t **dm = NULL;
    size_t dmc = registration_get_regs(NULL, ext_num, &dm);
    ext_reg_t *reg = dmc > 0 ? dm[0] : NULL;
    free(dm);
    if (!reg) {
      char pat_sec2[128];
      resp_object *pat_sec2_obj = get_extension_section(ext_num, pat_sec2, sizeof(pat_sec2));
      if (pat_sec2_obj) {
        const char *section_tail2 = (strlen(pat_sec2) > 4) ? pat_sec2 + 4 : "";
        resp_free(pat_sec2_obj);
        if (section_tail2[0] && strcmp(section_tail2, ext_num) != 0) {
          dm = NULL;
          dmc = registration_get_regs(NULL, section_tail2, &dm);
          reg = dmc > 0 ? dm[0] : NULL;
          free(dm);
        }
      }
    }
    const char *destination = to_user[0] ? to_user : "";
    char *target_override = NULL;
    char **trunk_override = NULL;
    int trunk_override_n = -1;
    int dialout_action = 0;
    int reject_code = 403;
    config_trunk *primary_trunk = (reg && reg->trunk_name && reg->trunk_name[0])
      ? get_trunk_config(cfg, reg->trunk_name) : resolve_trunk_for_extension(cfg, ext_num);
    config_trunk *dialout_group_trunks[64];
    size_t n_dialout_group = get_group_trunks(cfg, primary_trunk, dialout_group_trunks, 64);
    if (plugin_count() > 0) {
      log_debug("call.dialout: querying plugins for ext %s -> %s call=%.32s", ext_num, destination, call_id);
      plugin_query_dialout(cfg, ext_num, destination, call_id, dialout_group_trunks, n_dialout_group,
        &dialout_action, &reject_code, &target_override, &trunk_override, &trunk_override_n);
    }

    /* 1c. DIALOUT plugin rejected → send error to caller. */
    if (dialout_action == 1) {
      log_info("call.dialout: plugin rejected call from %s to %s (code %d)", ext_num, destination, reject_code);
      free(ext_num);
      send_reply(ctx, buf, len, reject_code, 0, 0);
      free(target_override);
      return;
    }

    /* Apply target override from DIALOUT plugin if provided. */
    const char *cur_buf = buf;
    size_t cur_len = len;
    char *override_buf = NULL;
    if (dialout_action == 2 && target_override && target_override[0]) {
      log_info("call.dialout: plugin overrode target to %s for call %.32s", target_override, call_id);
      char req_host[256], req_port[32];
      if (sip_request_uri_host_port(buf, len, req_host, sizeof(req_host), req_port, sizeof(req_port))) {
        override_buf = build_invite_with_uri(buf, len, target_override, req_host, req_port);
        if (override_buf) { cur_buf = override_buf; cur_len = strlen(override_buf); }
      }
    }
    free(target_override);

    /* 1d. Destination matches a DID → call.dialin fires too, then route internally.
     * This covers extensions on different trunks calling each other via DID:
     * the recipient trunk sees it as a normal incoming call. */
    config_trunk *did_trunk = to_user[0] ? find_trunk_by_did(cfg, to_user) : NULL;
    if (did_trunk) {
      ext_reg_t **exts = NULL;
      size_t n_ext = get_group_regs(cfg, did_trunk, &exts);

      /* Fire call.dialin for the recipient trunk. */
      log_info("new call: ext %s -> DID %s (trunk %s, %zu target(s))", ext_num, to_user, did_trunk->name, n_ext);
      if (plugin_count() > 0 && n_ext > 0 && exts) {
        const char **ext_numbers = (const char **)malloc(n_ext * sizeof(const char *));
        if (ext_numbers) {
          for (size_t i = 0; i < n_ext; i++) ext_numbers[i] = exts[i]->number;
          int dialin_action = 0;
          int dialin_reject_code = 403;
          char **dialin_override_targets = NULL;
          size_t n_dialin_override = 0;
          log_debug("call.dialin: querying plugins for DID %s on trunk %s, call=%.32s", to_user, did_trunk->name, call_id);
          plugin_query_dialin(did_trunk->name, to_user, ext_numbers, n_ext, call_id,
            &dialin_action, &dialin_reject_code, &dialin_override_targets, &n_dialin_override);
          free(ext_numbers);
          if (dialin_action == 1) {
            log_info("call.dialin: plugin rejected call to DID %s (code %d)", to_user, dialin_reject_code);
            free(exts);
            free(ext_num);
            free(override_buf);
            send_reply(ctx, buf, len, dialin_reject_code, 0, 0);
            return;
          }
          if (dialin_action == 2 && dialin_override_targets && n_dialin_override > 0) {
            log_info("call.dialin: plugin overrode targets for DID %s (%zu target(s))", to_user, n_dialin_override);
            free(exts);
            free(ext_num);
            handle_invite_incoming(cfg, cur_buf, cur_len, ctx, to_user, (const char **)dialin_override_targets, n_dialin_override);
            for (size_t i = 0; i < n_dialin_override; i++) free(dialin_override_targets[i]);
            free(dialin_override_targets);
            free(override_buf);
            return;
          }
          if (dialin_override_targets) {
            for (size_t i = 0; i < n_dialin_override; i++) free(dialin_override_targets[i]);
            free(dialin_override_targets);
          }
        }
      }
      if (exts) free(exts);
      free(ext_num);
      handle_invite_incoming(cfg, cur_buf, cur_len, ctx, to_user, NULL, 0);
      free(override_buf);
      return;
    }

    /* 1e. Not a DID → route externally via extension's trunk. */
    log_info("new call: ext %s -> external %s (outgoing via trunk)", from_ext, to_user);
    free(ext_num);
    handle_invite_outgoing(cfg, cur_buf, cur_len, ctx, from_user, (const char **)trunk_override, trunk_override_n);
    if (trunk_override_n >= 0 && trunk_override) {
      for (int i = 0; i < trunk_override_n; i++) free(trunk_override[i]);
      free(trunk_override);
    }
    free(override_buf);
    return;
  }

  /* 2. Destination matches a DID (external caller, not from a known extension) */
  if (to_user[0] && find_trunk_by_did(cfg, to_user)) {
    config_trunk *trunk = find_trunk_by_did(cfg, to_user);
    ext_reg_t **exts = NULL;
    size_t n_ext = get_group_regs(cfg, trunk, &exts);
    log_info("new call: incoming from %s to DID %s (trunk %s, %zu target(s))", from_user[0] ? from_user : "(external)", to_user, trunk->name, n_ext);
    if (plugin_count() > 0 && n_ext > 0 && exts) {
      const char **ext_numbers = (const char **)malloc(n_ext * sizeof(const char *));
      if (ext_numbers) {
        for (size_t i = 0; i < n_ext; i++) ext_numbers[i] = exts[i]->number;
        int action = 0;
        int reject_code = 403;
        char **override_targets = NULL;
        size_t n_override = 0;
        log_debug("call.dialin: querying plugins for DID %s on trunk %s, call=%.32s", to_user, trunk->name, call_id);
        plugin_query_dialin(trunk->name, to_user, ext_numbers, n_ext, call_id,
          &action, &reject_code, &override_targets, &n_override);
        free(ext_numbers);
        if (action == 1) {
          log_info("call.dialin: plugin rejected incoming call to DID %s (code %d)", to_user, reject_code);
          free(exts);
          send_reply(ctx, buf, len, reject_code, 0, 0);
          return;
        }
        if (action == 2 && override_targets && n_override > 0) {
          log_info("call.dialin: plugin overrode targets for DID %s (%zu target(s))", to_user, n_override);
          free(exts);
          handle_invite_incoming(cfg, buf, len, ctx, to_user, (const char **)override_targets, n_override);
          for (size_t i = 0; i < n_override; i++) free(override_targets[i]);
          free(override_targets);
          return;
        }
        if (override_targets) {
          for (size_t i = 0; i < n_override; i++) free(override_targets[i]);
          free(override_targets);
        }
      }
    }
    if (exts) free(exts);
    handle_invite_incoming(cfg, buf, len, ctx, to_user, NULL, 0);
    return;
  }

  /* 2b. Trunk with filter_incoming=0: accept any number matching a registered extension */
  if (to_user[0]) {
    /* Find a trunk with filter_incoming=0 (the one that allowed this call through). */
    config_trunk *fi_trunk = NULL;
    for (size_t i = 0; i < cfg->trunk_count; i++) {
      if (!cfg->trunks[i].filter_incoming) {
        fi_trunk = &cfg->trunks[i];
        break;
      }
    }
    char match_sec[128];
    resp_object *match_ext_sec = fi_trunk ? get_extension_section(to_user, match_sec, sizeof(match_sec)) : NULL;
    if (fi_trunk && match_ext_sec) {
      const char *match_ext_number = (strlen(match_sec) > 4) ? match_sec + 4 : to_user;
      config_trunk *ext_trunk = resolve_trunk_for_extension(cfg, match_ext_number);
      const char *fi_prefix  = fi_trunk->group_prefix  ? fi_trunk->group_prefix  : "";
      const char *ext_prefix = ext_trunk && ext_trunk->group_prefix ? ext_trunk->group_prefix : "";
      int same_group = (cfg->locality == 0) || (strcmp(fi_prefix, ext_prefix) == 0);
      if (!same_group && !cfg->cross_group_calls) {
        log_info("incoming call to %s blocked: cross-group not allowed (trunk %s group '%s', ext group '%s')",
                 to_user, fi_trunk->name, fi_prefix, ext_prefix);
        send_reply(ctx, buf, len, 403, 0, 0);
        return;
      }
      /* Route to the destination extension's group. */
      config_trunk *route_trunk = ext_trunk ? ext_trunk : fi_trunk;
      ext_reg_t **exts = NULL;
      size_t n_ext = get_group_regs(cfg, route_trunk, &exts);
      log_info("new call: incoming from %s to %s (trunk %s filter_incoming=0, %zu target(s))",
               from_user[0] ? from_user : "(external)", to_user, fi_trunk->name, n_ext);
      if (plugin_count() > 0 && n_ext > 0 && exts) {
        const char **ext_numbers = (const char **)malloc(n_ext * sizeof(const char *));
        if (ext_numbers) {
          for (size_t i = 0; i < n_ext; i++) ext_numbers[i] = exts[i]->number;
          int action = 0;
          int reject_code = 403;
          char **override_targets = NULL;
          size_t n_override = 0;
          log_debug("call.dialin: querying plugins (filter_incoming=0) for %s on trunk %s, call=%.32s", to_user, fi_trunk->name, call_id);
          plugin_query_dialin(fi_trunk->name, to_user, ext_numbers, n_ext, call_id,
            &action, &reject_code, &override_targets, &n_override);
          free(ext_numbers);
          if (action == 1) {
            log_info("call.dialin: plugin rejected incoming call to %s (code %d)", to_user, reject_code);
            free(exts);
            send_reply(ctx, buf, len, reject_code, 0, 0);
            return;
          }
          if (action == 2 && override_targets && n_override > 0) {
            log_info("call.dialin: plugin overrode targets for %s (%zu target(s))", to_user, n_override);
            free(exts);
            handle_invite_incoming(cfg, buf, len, ctx, to_user, (const char **)override_targets, n_override);
            for (size_t i = 0; i < n_override; i++) free(override_targets[i]);
            free(override_targets);
            return;
          }
          if (override_targets) {
            for (size_t i = 0; i < n_override; i++) free(override_targets[i]);
            free(override_targets);
          }
        }
      }
      resp_free(match_ext_sec);
      if (exts) free(exts);
      handle_invite_incoming(cfg, buf, len, ctx, to_user, NULL, 0);
      return;
    }
    if (match_ext_sec) resp_free(match_ext_sec);
  }

  /* 3. Fallback: from_user with @, extension prefix match → outgoing */
  if (from_user[0]) {
    const char *at = strchr(from_user, '@');
    size_t ext_len = at ? (size_t)(at - from_user) : strlen(from_user);
    char *ext_num = (char *)malloc(ext_len + 1);
    if (ext_num) {
      memcpy(ext_num, from_user, ext_len);
      ext_num[ext_len] = '\0';
      {
        resp_object *s3 = get_extension_section(ext_num, NULL, 0);
        if (s3) {
          resp_free(s3);
          free(ext_num);
          handle_invite_outgoing(cfg, buf, len, ctx, from_user, NULL, -1);
          return;
        }
      }
      free(ext_num);
    }
  }

  /* 4. No match → 404 */
  send_reply(ctx, buf, len, 404, 0, 0);
}

/* Format peer address for logging. */
static void peer_to_str(const struct sockaddr_storage *peer, socklen_t peerlen, char *buf, size_t buf_size) {
  if (peerlen >= sizeof(struct sockaddr_in) && peer->ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)peer;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    snprintf(buf, buf_size, "%s:%u", ip, (unsigned)ntohs(sin->sin_port));
  } else {
    snprintf(buf, buf_size, "(unknown)");
  }
}

/* Forward a SIP response from a forked leg back to the caller.
 * Uses forward-and-rewrite: strip our top Via, rewrite SDP c=/m= for
 * the caller-facing RTP port, and sendto() to the caller. */
static void handle_sip_response(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx) {
  char call_id_buf[CALL_ID_MAX];
  call_id_buf[0] = '\0';
  sip_header_copy(buf, len, "Call-ID", call_id_buf, sizeof(call_id_buf));
  int code = sip_response_status_code(buf, len);
  char peer_str[64];
  peer_to_str(&ctx->peer, ctx->peerlen, peer_str, sizeof(peer_str));
  log_trace("handle_sip_response: from %s code=%d call=%.32s", peer_str, code, call_id_buf);

  call_t *call = call_find(call_id_buf);
  if (!call) {
    log_debug("SIP response: no matching call for Call-ID %.32s, dropping", call_id_buf);
    return;
  }

  /* Determine CSeq method: is this a response to CANCEL or INVITE? */
  char cseq_full[128];
  cseq_full[0] = '\0';
  sip_header_copy(buf, len, "CSeq", cseq_full, sizeof(cseq_full));
  int is_cancel_response = (strstr(cseq_full, "CANCEL") != NULL);

  /* Absorb responses to our own CANCEL (don't forward to caller). */
  if (is_cancel_response) {
    log_trace("SIP response: absorbing %d for CANCEL (CSeq: %s)", code, cseq_full);
    return;
  }

  /* Identify which fork responded. */
  const char *callee_num = NULL;
  size_t fork_idx = (size_t)-1;
  for (size_t f = 0; f < call->n_forks; f++) {
    if (sockaddr_match(&ctx->peer, ctx->peerlen, &call->fork_addrs[f], call->fork_lens[f])) {
      callee_num = call->fork_ids[f];
      fork_idx = f;
      break;
    }
  }
  if (!callee_num && call->dest_str) callee_num = call->dest_str;

  /* Chain rewrites: strip our Via, rewrite SDP if present. */
  char tmp1[SIP_READ_BUF_SIZE], tmp2[SIP_READ_BUF_SIZE];
  int cur_len;

  /* 1. Strip our top Via. */
  cur_len = sip_strip_top_via(buf, len, tmp1, sizeof(tmp1));
  if (cur_len < 0) { log_error("SIP response: strip_top_via failed for call %.32s", call_id_buf); return; }

  /* 2. On 2xx with SDP: learn callee RTP address, rewrite SDP for caller. */
  if (code >= 200 && code < 300) {
    const char *resp_body;
    size_t resp_body_len;
    if (sip_request_get_body(tmp1, (size_t)cur_len, &resp_body, &resp_body_len) && resp_body_len > 0) {
      /* Parse callee SDP to learn party B's RTP address. */
      sdp_media_t sdp_media[SDP_MAX_MEDIA];
      size_t sdp_n = 0;
      if (sdp_parse_media(resp_body, resp_body_len, sdp_media, SDP_MAX_MEDIA, &sdp_n) == 0 && sdp_n > 0) {
        inet_aton(sdp_media[0].ip, &call->rtp_remote_b.sin_addr);
        call->rtp_remote_b.sin_family = AF_INET;
        call->rtp_remote_b.sin_port   = htons((uint16_t)sdp_media[0].port);
        log_debug("RTP: callee %s RTP at %s:%d", callee_num ? callee_num : "?",
                 sdp_media[0].ip, sdp_media[0].port);
      }

      /* Rewrite SDP: advertise our caller-facing port (rtp_port_a). */
      char via_host[256], via_port[32];
      if (call->rtp_port_a > 0 &&
          get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0) {
        char new_sdp[4096];
        int sdp_len = sdp_rewrite_addr(resp_body, resp_body_len, via_host, call->rtp_port_a, new_sdp, sizeof(new_sdp));
        if (sdp_len > 0) {
          int new_len = sip_rewrite_body(tmp1, (size_t)cur_len, new_sdp, (size_t)sdp_len, tmp2, sizeof(tmp2));
          if (new_len > 0) {
            memcpy(tmp1, tmp2, (size_t)new_len);
            cur_len = new_len;
          }
        }
      }
    }
  }

  /* 3. Rewrite Contact in responses to point to PBX (keeps ACK/BYE in the signaling path). */
  {
    char via_host[256], via_port[32];
    if (get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0) {
      char contact_val[256];
      const char *user_part = callee_num ? callee_num : (call->dest_str ? call->dest_str : "");
      sip_format_contact_uri_value(user_part, via_host, via_port, contact_val, sizeof(contact_val));
      int rw_len = sip_rewrite_header(tmp1, (size_t)cur_len, "Contact", contact_val, tmp2, sizeof(tmp2));
      if (rw_len > 0) { memcpy(tmp1, tmp2, (size_t)rw_len); cur_len = rw_len; }
    }
  }

  /* Decide whether to forward this response to the caller */
  int should_forward = 1;

  /* ACK non-2xx final responses back to callee (RFC 3261 §17.1.1.3). */
  if (code >= 300) {
    char ack_cseq[64];
    int ack_cseq_num = get_cseq_number(buf, len);
    snprintf(ack_cseq, sizeof(ack_cseq), "%d ACK", ack_cseq_num);
    char ack_req_uri[256];
    ack_req_uri[0] = '\0';
    if (fork_idx != (size_t)-1)
      fork_uri_from_addr(&call->fork_addrs[fork_idx], call->fork_ids[fork_idx], ack_req_uri, sizeof(ack_req_uri));
    if (ack_req_uri[0]) {
      char ack_via[512], ack_from[384], ack_to[384], ack_callid[256];
      ack_via[0] = ack_from[0] = ack_to[0] = ack_callid[0] = '\0';
      sip_header_copy(buf, len, "Via", ack_via, sizeof(ack_via));
      sip_header_copy(buf, len, "From", ack_from, sizeof(ack_from));
      sip_header_copy(buf, len, "To", ack_to, sizeof(ack_to));
      sip_header_copy(buf, len, "Call-ID", ack_callid, sizeof(ack_callid));
      char *ack = sip_build_request_parts("ACK", ack_req_uri,
        ack_via, ack_from[0] ? ack_from : NULL, ack_to[0] ? ack_to : NULL,
        ack_callid[0] ? ack_callid : NULL, ack_cseq, NULL,
        0, NULL, 0, NULL);
      if (ack) {
        log_trace("SIP: ACK to callee at %s for %d", peer_str, code);
        udp_send_to(ctx->sockfd, (struct sockaddr *)&ctx->peer, ctx->peerlen, ack, strlen(ack));
        free(ack);
      }
    }

    /* Update per-fork state and decide whether to forward to caller. */
    if (fork_idx != (size_t)-1) {
      if (code == 486 && !call->cancelling) {
        /* 486 Busy: add extension to pending for retry when free. */
        call->fork_state[fork_idx] = FORK_BUSY;
        if (call->fork_ids[fork_idx] && call->n_pending_exts < CALL_MAX_FORKS) {
          call->pending_exts[call->n_pending_exts++] = strdup(call->fork_ids[fork_idx]);
        }
        log_debug("SIP response: fork %zu (%s) busy, added to pending for call %.32s", fork_idx,
                 call->fork_ids[fork_idx] ? call->fork_ids[fork_idx] : "?", call_id_buf);
        should_forward = 0; /* don't forward 486 to caller, others may still ring */
      } else {
        call->fork_state[fork_idx] = FORK_DONE;
      }
    }

    /* Check if all forks are done (no active forks remaining). */
    int all_done = 1;
    for (size_t f = 0; f < call->n_forks; f++) {
      if (call->fork_state[f] == FORK_ACTIVE) { all_done = 0; break; }
    }
    if (all_done && call->n_pending_exts == 0) {
      /* All forks finished and no pending retries: forward final response and clean up. */
      should_forward = 1;
    } else if (!all_done || call->n_pending_exts > 0) {
      /* Some forks still ringing or pending retries: absorb this response. */
      if (call->fork_state[fork_idx != (size_t)-1 ? fork_idx : 0] != FORK_ACTIVE)
        should_forward = 0;
    }
  }

  /* Forward the rewritten response to caller (if appropriate). */
  if (should_forward) {
    log_trace("SIP response: forwarding %d to caller (%zu bytes)", code, (size_t)cur_len);
    log_hexdump_trace(tmp1, (size_t)cur_len);
    udp_send_to(ctx->sockfd, (struct sockaddr *)&call->a.sip_addr, call->a.sip_len, tmp1, (size_t)cur_len);
  } else {
    log_trace("SIP response: absorbing %d (forks still active or pending)", code);
  }

  /* Update call state. */
  if (code >= 200 && code < 300) {
    log_debug("call answered: %.32s by %s", call_id_buf, callee_num ? callee_num : "?");
    call->answered = 1;
    call->answered_at = time(NULL);
    metrics_call_active();
    memcpy(&call->b.sip_addr, &ctx->peer, sizeof(ctx->peer));
    call->b.sip_len = ctx->peerlen;
    if (callee_num) {
      free(call->b.id);
      call->b.id = strdup(callee_num);
      free(call->dest_str);
      call->dest_str = strdup(callee_num);
    }
    /* Cancel all other active forks and clear pending — this extension answered. */
    cancel_active_forks(call, call->sockfd);
    clear_pending_exts(call);
    notify_call_answer(call->direction ? call->direction : "dialin", call->call_id, call->source_str, call->dest_str);
    /* Call stays alive for RTP; BYE or timeout will clean up. */
  } else if (code >= 300) {
    /* Check if all forks are done AND no pending → remove call. */
    int all_done = 1;
    for (size_t f = 0; f < call->n_forks; f++) {
      if (call->fork_state[f] == FORK_ACTIVE) { all_done = 0; break; }
    }
    if (all_done && call->n_pending_exts == 0) {
      call_remove(call);
    }
  }
}

/* One UDP datagram: peer address + message (flexible array). Caller frees. */
typedef struct {
  struct sockaddr_storage peer;
  socklen_t peerlen;
  size_t len;
  char buf[];
} udp_msg_t;

/* Handle one UDP datagram (SIP request or response). Called synchronously from main loop. */
static void handle_udp_msg(upbx_config *cfg, udp_msg_t *msg, int sockfd) {
  log_trace("%s", __func__);
  sip_send_ctx ctx;
  size_t len = msg->len;
  char *buf = msg->buf;

  ctx.sockfd = sockfd;
  memcpy(&ctx.peer, &msg->peer, sizeof(ctx.peer));
  ctx.peerlen = msg->peerlen;

  if (!looks_like_sip(buf, len)) {
    free(msg);
    return;
  }
  if (len >= SIP_READ_BUF_SIZE) {
    free(msg);
    return;
  }
  buf[len] = '\0';
  if (!sip_security_check_raw(buf, len + 1)) {
    free(msg);
    return;
  }
  log_hexdump_trace(buf, len);

  if (!sip_is_request(buf, len)) {
    handle_sip_response(cfg, buf, len, &ctx);
    free(msg);
    return;
  }

  const char *method = NULL;
  size_t method_len = 0;
  if (!sip_request_method(buf, len, &method, &method_len)) {
    free(msg);
    return;
  }
  if (method_len == 8 && strncasecmp(method, "REGISTER", 8) == 0) {
    log_trace("REGISTER: step udp_msg calling handle_register");
    handle_register(buf, len, cfg, &ctx);
    log_trace("REGISTER: step udp_msg handle_register returned");
  } else if (method_len == 6 && strncasecmp(method, "INVITE", 6) == 0) {
    handle_invite(cfg, buf, len, &ctx);
  } else if (method_len == 3 && strncasecmp(method, "ACK", 3) == 0) {
    /* ACK: for 2xx → forward to callee; for non-2xx → absorb (we already sent our own ACK). */
    char cid[CALL_ID_MAX];
    cid[0] = '\0';
    sip_header_copy(buf, len, "Call-ID", cid, sizeof(cid));
    call_t *c = call_find(cid);
    if (c && c->answered && c->b.sip_len > 0) {
      /* Forward ACK to callee with Request-URI rewritten and our Via prepended. */
      char via_host[256], via_port[32];
      if (get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0) {
        char t1[SIP_READ_BUF_SIZE], t2[SIP_READ_BUF_SIZE];
        int clen = (int)len;
        memcpy(t1, buf, len);

        /* Rewrite Request-URI to point to the callee. */
        {
          char req_uri[256];
          if (fork_uri_from_addr(&c->b.sip_addr, c->b.id, req_uri, sizeof(req_uri)) == 0) {
            int rw = sip_rewrite_request_uri(t1, (size_t)clen, req_uri, t2, sizeof(t2));
            if (rw > 0) { memcpy(t1, t2, (size_t)rw); clen = rw; }
          }
        }

        /* Prepend our Via. */
        char via_val[256];
        sip_make_via_line(via_host, via_port, via_val, sizeof(via_val));
        int plen = sip_prepend_via(t1, (size_t)clen, via_val, t2, sizeof(t2));
        if (plen > 0) {
          log_debug("SIP: forwarding ACK to callee for call %.32s", cid);
          udp_send_to(sockfd, (struct sockaddr *)&c->b.sip_addr, c->b.sip_len, t2, (size_t)plen);
        }
      }
    } else {
      log_trace("SIP: absorbing ACK for call %.32s (non-2xx or no call)", cid);
    }
  } else if (method_len == 3 && strncasecmp(method, "BYE", 3) == 0) {
    /* BYE: forward to other party, respond 200 OK, clean up call. */
    char cid[CALL_ID_MAX];
    cid[0] = '\0';
    sip_header_copy(buf, len, "Call-ID", cid, sizeof(cid));
    call_t *c = call_find(cid);
    if (c) {
      /* Determine who sent the BYE and forward to the other side. */
      int from_a = sockaddr_match(&ctx.peer, ctx.peerlen,
                                  (struct sockaddr_storage *)&c->a.sip_addr, c->a.sip_len);
      struct sockaddr_storage *fwd_addr;
      socklen_t fwd_len;
      if (from_a && c->b.sip_len > 0) {
        fwd_addr = &c->b.sip_addr;
        fwd_len  = c->b.sip_len;
      } else if (c->a.sip_len > 0) {
        fwd_addr = &c->a.sip_addr;
        fwd_len  = c->a.sip_len;
      } else {
        fwd_addr = NULL;
        fwd_len  = 0;
      }
      /* Forward BYE with our Via. */
      if (fwd_addr && fwd_len > 0) {
        char via_host[256], via_port[32];
        if (get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0) {
          char via_val[256];
          sip_make_via_line(via_host, via_port, via_val, sizeof(via_val));
          char t1[SIP_READ_BUF_SIZE];
          int clen = sip_prepend_via(buf, len, via_val, t1, sizeof(t1));
          if (clen > 0) {
            log_debug("SIP: forwarding BYE for call %.32s", cid);
            udp_send_to(sockfd, (struct sockaddr *)fwd_addr, fwd_len, t1, (size_t)clen);
          }
        }
      }
      /* Reply 200 OK to the BYE sender. */
      send_reply(&ctx, buf, len, 200, 0, 0);
      call_remove(c);
    } else {
      /* No matching call; reply 481 Call/Transaction Does Not Exist. */
      send_reply(&ctx, buf, len, 481, 0, 0);
    }
  } else if (method_len == 6 && strncasecmp(method, "CANCEL", 6) == 0) {
    /* CANCEL: reply 200, send 487 to caller, clean up. */
    char cid[CALL_ID_MAX];
    cid[0] = '\0';
    sip_header_copy(buf, len, "Call-ID", cid, sizeof(cid));
    call_t *c = call_find(cid);
    /* Reply 200 OK to the CANCEL. */
    send_reply(&ctx, buf, len, 200, 0, 0);
    if (c && !c->answered) {
      cancel_active_forks(c, sockfd);
      clear_pending_exts(c);
      c->cancelling = 1;
    }
  } else {
    send_reply(&ctx, buf, len, 501, 0, 0);
  }
  free(msg);
}

/* Parse "host:port" into host and port; return 0 on success. */
static int parse_listen_addr(const char *addr, char *host, size_t host_size, char *port, size_t port_size) {
  const char *colon = strrchr(addr, ':');
  if (!colon || colon == addr) return -1;
  size_t host_len = (size_t)(colon - addr);
  if (host_len >= host_size) return -1;
  memcpy(host, addr, host_len);
  host[host_len] = '\0';
  if (strlen(colon + 1) >= port_size) return -1;
  strncpy(port, colon + 1, port_size - 1);
  port[port_size - 1] = '\0';
  return 0;
}

/* Get host and port to advertise in Via/SDP: learned from REGISTER Request-URI, else listen. Return 0 on success. */
static int get_advertise_addr(upbx_config *cfg, char *host_out, size_t host_size, char *port_out, size_t port_size);

/* Like get_advertise_addr but for a specific extension: use that extension's learned address (from its REGISTER) so Via/Contact match how that extension sees us. */
static int get_advertise_addr_for_ext(upbx_config *cfg, const ext_reg_t *reg, char *host_out, size_t host_size, char *port_out, size_t port_size) {
  if (reg && reg->learned_host[0]) {
    size_t n = strlen(reg->learned_host);
    if (n >= host_size) return -1;
    memcpy(host_out, reg->learned_host, n + 1);
    n = strlen(reg->learned_port);
    if (n > 0 && n < port_size) memcpy(port_out, reg->learned_port, n + 1);
    else if (port_size > 0) { strncpy(port_out, "5060", port_size - 1); port_out[port_size - 1] = '\0'; }
    return 0;
  }
  return get_advertise_addr(cfg, host_out, host_size, port_out, port_size);
}

static int get_advertise_addr(upbx_config *cfg, char *host_out, size_t host_size, char *port_out, size_t port_size) {
  const char *listen = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  if (registration_get_advertise_addr(host_out, host_size, port_out, port_size)) {
    return 0;
  }
  return parse_listen_addr(listen, host_out, host_size, port_out, port_size);
}

static int resolve_interface_to_in_addr(const char *ifname, struct in_addr *out);

/* Resolve interface name (e.g. en0, eth0) to IPv4 address. Return 0 on success. */
static int resolve_interface_to_in_addr(const char *ifname, struct in_addr *out) {
  struct ifaddrs *ifa_list = NULL, *ifa;
  if (getifaddrs(&ifa_list) != 0) return -1;
  for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
    if (strcmp(ifa->ifa_name, ifname) != 0) continue;
    struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
    out->s_addr = sin->sin_addr.s_addr;
    freeifaddrs(ifa_list);
    return 0;
  }
  freeifaddrs(ifa_list);
  return -1;
}

/* Create and bind UDP socket; return fd or -1. Binds to host:port; host may be an IP, hostname, or interface name (e.g. en0). */
static int udp_bind(const char *listen_addr) {
  char host[256], port[32];
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  int ret;

  if (parse_listen_addr(listen_addr, host, sizeof(host), port, sizeof(port)) != 0)
    return -1;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  ret = getaddrinfo(host[0] ? host : NULL, port, &hints, &res);
  if (ret != 0 || !res) {
    /* Host might be an interface name (e.g. en0); resolve via getifaddrs. */
    struct in_addr if_addr;
    if (resolve_interface_to_in_addr(host, &if_addr) == 0) {
      struct sockaddr_in sin;
      unsigned short port_num = (unsigned short)atoi(port);
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_addr = if_addr;
      sin.sin_port = htons(port_num);
      fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if (fd >= 0 && bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
        if (set_socket_nonblocking(fd, 1) != 0) {
          close(fd);
          fd = -1;
        }
        return fd;
      }
      if (fd >= 0) close(fd);
    }
    return -1;
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return -1;
  if (set_socket_nonblocking(fd, 1) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

/* Main loop: select on SIP + RTP + trunk fds, dispatch, run protothreads. */
void daemon_root(int argc, void *argv[]) {
  upbx_config *cfg = (upbx_config *)argv[0];
  if (argc < 1 || !cfg) return;

  const char *listen_addr = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  log_info("SIP binding to %s", listen_addr);
  int sockfd = udp_bind(listen_addr);
  if (sockfd < 0) {
    log_fatal("daemon_root: UDP bind %s failed", listen_addr);
    return;
  }
  log_info("SIP listening on UDP %s", listen_addr);

  /* Register callback so all call removals (including timeout aging) fire call.hangup. */
  call_set_pre_remove_callback(call_pre_remove_handler);

  /* Initialize registration subsystem. */
  registration_init();

  log_info("trunk registration started");
  notify_extension_and_trunk_lists(cfg);

  trunk_reg_start();
  api_start();
  metrics_init();

  PT_INIT(&pt_overflow);
  struct pt pt_trunk_reg;
  PT_INIT(&pt_trunk_reg);
  struct pt pt_api;
  PT_INIT(&pt_api);
  struct pt pt_reg_expiry;
  PT_INIT(&pt_reg_expiry);
  struct pt pt_metrics;
  PT_INIT(&pt_metrics);

  char buf[SIP_READ_BUF_SIZE];
  struct sockaddr_storage peer;
  socklen_t peerlen;

  for (;;) {
    plugmod_tick();
    plugin_sync();
    time_t loop_timestamp = time(NULL);

    fd_set r;
    FD_ZERO(&r);
    FD_SET(sockfd, &r);
    int maxfd = sockfd;
    call_fill_rtp_fds(&r, &maxfd);
    trunk_reg_fill_fds(&r, &maxfd);
    api_fill_fds(&r, &maxfd);

    struct timeval tv = { 0, 50000 }; /* 50ms */
    int n = select(maxfd + 1, &r, NULL, NULL, &tv);
    if (n > 0) {
      if (FD_ISSET(sockfd, &r)) {
        peerlen = sizeof(peer);
        ssize_t nr = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
        if (nr > 0 && (size_t)nr <= SIP_READ_BUF_SIZE - 1) {
          char peer_str[64];
          if (peer.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&peer;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            snprintf(peer_str, sizeof(peer_str), "%s:%u", ip, (unsigned)ntohs(sin->sin_port));
          } else {
            snprintf(peer_str, sizeof(peer_str), "(non-IPv4)");
          }
          log_trace("SIP packet from %s (%zd bytes)", peer_str, (size_t)nr);
          udp_msg_t *msg = malloc(sizeof(udp_msg_t) + (size_t)nr + 1);
          if (msg) {
            memcpy(&msg->peer, &peer, sizeof(msg->peer));
            msg->peerlen = peerlen;
            msg->len = (size_t)nr;
            memcpy(msg->buf, buf, (size_t)nr);
            msg->buf[nr] = '\0';
            handle_udp_msg(cfg, msg, sockfd);
          }
          if (registration_is_notify_pending()) {
            registration_clear_notify_pending();
            notify_extension_and_trunk_lists(cfg);
          }
        }
      }
      call_relay_rtp(&r);
      trunk_reg_poll(&r);
    }
    PT_SCHEDULE(overflow_pt(&pt_overflow, cfg, sockfd));
    PT_SCHEDULE(trunk_reg_pt(&pt_trunk_reg));
    PT_SCHEDULE(api_pt(&pt_api, &r, loop_timestamp));
    PT_SCHEDULE(registration_remove_expired_pt(&pt_reg_expiry, loop_timestamp));
    PT_SCHEDULE(metrics_tick_pt(&pt_metrics, loop_timestamp));
    call_age_idle(120); /* remove calls with no RTP for 2 minutes */
  }
}
