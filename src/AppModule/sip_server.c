/*
 * SIP server: listen on UDP, receive datagrams, parse SIP with minimal parser (no libosip2),
 * handle REGISTER (extension auth, registration store) and INVITE (call routing).
 * All I/O via tidwall/neco.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "tidwall/neco.h"
#include "AppModule/rtp_relay.h"
#include "rxi/log.h"
#include "config.h"
#include "AppModule/plugin.h"
#include "AppModule/sip_server.h"
#include "AppModule/sip_hexdump.h"
#include "AppModule/trunk_reg.h"
#include "AppModule/sip_parse.h"
#include "AppModule/md5.h"

#define SIP_READ_BUF_SIZE  (64 * 1024)
#define SIP_MAX_HEADERS    (32 * 1024)
#define AUTH_REALM         "upbx"
#define DEFAULT_EXPIRES    3600

/* Digest auth (RFC 2617) */
#define HASHLEN 16
#define HASHHEXLEN 32
typedef unsigned char HASH[HASHLEN];
typedef unsigned char HASHHEX[HASHHEXLEN + 1];

static void cvt_hex(const unsigned char *bin, HASHHEX hex) {
  for (int i = 0; i < HASHLEN; i++) {
    unsigned char j = (bin[i] >> 4) & 0xf;
    hex[i * 2] = (char)(j <= 9 ? j + '0' : j + 'a' - 10);
    j = bin[i] & 0xf;
    hex[i * 2 + 1] = (char)(j <= 9 ? j + '0' : j + 'a' - 10);
  }
  hex[HASHHEXLEN] = '\0';
}

static void digest_calc_ha1(const char *alg, const char *user, const char *realm,
    const char *password, const char *nonce, const char *cnonce, HASHHEX out) {
  MD5_CTX ctx;
  HASH ha1;
  MD5_Init(&ctx);
  if (user) MD5_Update(&ctx, (const unsigned char *)user, strlen(user));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (realm) MD5_Update(&ctx, (const unsigned char *)realm, strlen(realm));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (password) MD5_Update(&ctx, (const unsigned char *)password, strlen(password));
  MD5_Final(ha1, &ctx);
  if (alg && strcasecmp(alg, "md5-sess") == 0) {
    MD5_Init(&ctx);
    MD5_Update(&ctx, ha1, HASHLEN);
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (nonce) MD5_Update(&ctx, (const unsigned char *)nonce, strlen(nonce));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (cnonce) MD5_Update(&ctx, (const unsigned char *)cnonce, strlen(cnonce));
    MD5_Final(ha1, &ctx);
  }
  cvt_hex(ha1, out);
}

static void digest_calc_response(HASHHEX ha1, const char *nonce, const char *nc,
    const char *cnonce, const char *qop, const char *method, const char *uri,
    HASHHEX hentity, HASHHEX out) {
  MD5_CTX ctx;
  HASH ha2, resphash;
  HASHHEX ha2hex;
  MD5_Init(&ctx);
  if (method) MD5_Update(&ctx, (const unsigned char *)method, strlen(method));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (uri) MD5_Update(&ctx, (const unsigned char *)uri, strlen(uri));
  /* RFC 2617: for qop=auth-int only, HA2 = MD5(method:uri:MD5(entity)); for qop=auth, HA2 = MD5(method:uri) */
  if (qop && strcasecmp(qop, "auth-int") == 0 && hentity) {
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    MD5_Update(&ctx, (const unsigned char *)hentity, HASHHEXLEN);
  }
  MD5_Final(ha2, &ctx);
  cvt_hex(ha2, ha2hex);
  MD5_Init(&ctx);
  MD5_Update(&ctx, (const unsigned char *)ha1, HASHHEXLEN);
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (nonce) MD5_Update(&ctx, (const unsigned char *)nonce, strlen(nonce));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (nc) MD5_Update(&ctx, (const unsigned char *)nc, strlen(nc));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (cnonce) MD5_Update(&ctx, (const unsigned char *)cnonce, strlen(cnonce));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (qop && *qop) MD5_Update(&ctx, (const unsigned char *)qop, strlen(qop));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  MD5_Update(&ctx, (const unsigned char *)ha2hex, HASHHEXLEN);
  MD5_Final(resphash, &ctx);
  cvt_hex(resphash, out);
}

static char *auth_generate_nonce(void) {
  static char nonce[48];
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  /* Unquoted so digest calculation uses the same value we send and we parse back */
  snprintf(nonce, sizeof(nonce), "%lx%lx%x",
      (long)ts.tv_sec, (long)ts.tv_nsec, (unsigned)rand());
  return nonce;
}

/* Extension registration (runtime state) */
typedef struct {
  char *number;
  char *trunk_name;
  char *contact;
  char *plugin_data;  /* Optional custom data from plugin ALLOW (e.g. external auth token) */
  time_t expires;
} ext_reg_t;

static ext_reg_t *reg_list;
static size_t reg_count;
static size_t reg_cap;
static neco_mutex reg_mutex;
static int reg_mutex_initialized;

/* Build WWW-Authenticate header line for 401. Caller frees. */
static char *build_www_authenticate(void) {
  const char *nonce = auth_generate_nonce();
  char *out = NULL;
  if (asprintf(&out, "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\"", AUTH_REALM, nonce) < 0)
    return NULL;
  return out;
}

static config_extension *get_extension_config(upbx_config *cfg, const char *number) {
  for (size_t i = 0; i < cfg->extension_count; i++)
    if (strcmp(cfg->extensions[i].number, number) == 0)
      return &cfg->extensions[i];
  return NULL;
}

static config_trunk *get_trunk_config(upbx_config *cfg, const char *name) {
  for (size_t i = 0; i < cfg->trunk_count; i++)
    if (strcmp(cfg->trunks[i].name, name) == 0)
      return &cfg->trunks[i];
  return NULL;
}

/* Resolve trunk for extension: from @trunk in username, or by locality/group. */
static config_trunk *resolve_trunk_for_extension(upbx_config *cfg,
    const char *ext_number, const char *username) {
  const char *at = strchr(username, '@');
  if (at && at[1]) {
    char *trunk_name = strdup(at + 1);
    if (!trunk_name) return NULL;
    config_trunk *t = get_trunk_config(cfg, trunk_name);
    free(trunk_name);
    return t;
  }
  if (cfg->locality > 0) {
    size_t ext_len = strlen(ext_number);
    if (ext_len > (size_t)cfg->locality) {
      for (size_t i = 0; i < cfg->trunk_count; i++) {
        if (!cfg->trunks[i].group_prefix) continue;
        size_t pre_len = strlen(cfg->trunks[i].group_prefix);
        if (ext_len >= pre_len + (size_t)cfg->locality &&
            strncmp(ext_number, cfg->trunks[i].group_prefix, pre_len) == 0)
          return &cfg->trunks[i];
      }
    }
  }
  return NULL;
}

/* True if number is configured as emergency. */
static int is_emergency_number(upbx_config *cfg, const char *number) {
  if (!number || !cfg || !cfg->emergency) return 0;
  for (size_t i = 0; i < cfg->emergency_count; i++)
    if (cfg->emergency[i] && strcmp(cfg->emergency[i], number) == 0)
      return 1;
  return 0;
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

/* Get trunk name for extension from reg_list ("" if not registered). Caller does not free. */
static const char *get_trunk_for_extension(const char *ext_number) {
  time_t now = time(NULL);
  if (!reg_mutex_initialized || !ext_number) return "";
  neco_mutex_lock(&reg_mutex);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].number, ext_number) == 0) {
      const char *t = reg_list[i].trunk_name ? reg_list[i].trunk_name : "";
      neco_mutex_unlock(&reg_mutex);
      return t;
    }
  }
  neco_mutex_unlock(&reg_mutex);
  return "";
}

/* Notify plugins of extension list (number, name, trunk per ext) and trunk list (name, group, dids, cid, exts per trunk). */
static void notify_extension_and_trunk_lists(upbx_config *cfg) {
  if (plugin_count() == 0) return;
  size_t i, j;
  const char **argv;
  size_t argc;

  /* EXTENSION.LIST: 3 args per extension (number, name, trunk); no secret */
  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "EXTENSION.LIST")) break;
  }
  if (i < plugin_count()) {
    argc = 3 * cfg->extension_count;
    argv = argc ? (const char **)malloc(argc * sizeof(const char *)) : NULL;
    if (argv) {
      char **trunk_copies = (char **)calloc(cfg->extension_count, sizeof(char *));
      if (trunk_copies) {
        for (i = 0; i < cfg->extension_count; i++) {
          config_extension *e = &cfg->extensions[i];
          argv[i * 3 + 0] = e->number ? e->number : "";
          argv[i * 3 + 1] = e->name ? e->name : "";
          trunk_copies[i] = strdup(get_trunk_for_extension(e->number));
          argv[i * 3 + 2] = trunk_copies[i] ? trunk_copies[i] : "";
        }
        plugin_notify_event("EXTENSION.LIST", (int)argc, argv);
        for (i = 0; i < cfg->extension_count; i++) free(trunk_copies[i]);
        free(trunk_copies);
      }
      free(argv);
    }
  }

  /* TRUNK.LIST: 5 args per trunk (name, group_prefix, dids, cid, extensions); no credentials */
  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "TRUNK.LIST")) break;
  }
  if (i < plugin_count()) {
    argc = 5 * cfg->trunk_count;
    argv = argc ? (const char **)malloc(argc * sizeof(const char *)) : NULL;
    if (argv) {
      char **dids_strs = (char **)calloc(cfg->trunk_count, sizeof(char *));
      char **exts_strs = (char **)calloc(cfg->trunk_count, sizeof(char *));
      if (dids_strs && exts_strs) {
        for (i = 0; i < cfg->trunk_count; i++) {
          config_trunk *t = &cfg->trunks[i];
          argv[i * 5 + 0] = t->name ? t->name : "";
          argv[i * 5 + 1] = t->group_prefix ? t->group_prefix : "";
          if (t->did_count > 0) {
            size_t need = 1;
            for (j = 0; j < t->did_count; j++)
              need += (t->dids[j] ? strlen(t->dids[j]) : 0) + 1;
            dids_strs[i] = malloc(need);
            if (dids_strs[i]) {
              dids_strs[i][0] = '\0';
              for (j = 0; j < t->did_count; j++) {
                if (j) strcat(dids_strs[i], ",");
                if (t->dids[j]) strcat(dids_strs[i], t->dids[j]);
              }
              argv[i * 5 + 2] = dids_strs[i];
            } else
              argv[i * 5 + 2] = "";
          } else
            argv[i * 5 + 2] = "";
          argv[i * 5 + 3] = t->cid ? t->cid : "";
          exts_strs[i] = malloc(512);
          if (exts_strs[i]) {
            time_t now = time(NULL);
            exts_strs[i][0] = '\0';
            neco_mutex_lock(&reg_mutex);
            for (j = 0; j < reg_count; j++) {
              if (reg_list[j].expires <= now) continue;
              if (strcmp(reg_list[j].trunk_name, t->name) != 0) continue;
              if (exts_strs[i][0]) strcat(exts_strs[i], ",");
              if (reg_list[j].number) strcat(exts_strs[i], reg_list[j].number);
            }
            neco_mutex_unlock(&reg_mutex);
            argv[i * 5 + 4] = exts_strs[i];
          } else
            argv[i * 5 + 4] = "";
        }
        plugin_notify_event("TRUNK.LIST", (int)argc, argv);
        for (i = 0; i < cfg->trunk_count; i++) {
          free(dids_strs[i]);
          free(exts_strs[i]);
        }
      }
      free(dids_strs);
      free(exts_strs);
      free(argv);
    }
  }
}

/* One fork destination (extension we sent INVITE to). */
typedef struct {
  struct sockaddr_storage peer;
  socklen_t peerlen;
  char *ext_number;  /* extension that is being rung (for CALL.ANSWER) */
} fork_peer_t;

/* Incoming call state: DID call forked to extensions; we track it for response forwarding and overflow. */
typedef struct incoming_call {
  struct incoming_call *next;
  char *call_id;
  int sockfd;
  struct sockaddr_storage caller_peer;
  socklen_t caller_peerlen;
  config_trunk *trunk;
  fork_peer_t *forks;
  size_t n_forks;
  int overflow_done;  /* 1 = already applied overflow or no overflow */
  int answered;       /* 1 = we forwarded 2xx to caller */
  char *original_invite;  /* serialized INVITE for make_reply(486) etc. */
  size_t original_invite_len;
  char *source_str;   /* DID (for CALL.ANSWER/HANGUP) */
  char *dest_str;     /* answering extension (set on 2xx) */
  time_t answered_at; /* when 2xx was received (for duration) */
} incoming_call_t;

static int sockaddr_match(const struct sockaddr_storage *a, socklen_t alen, const struct sockaddr_storage *b, socklen_t blen) {
  if (alen != blen) return 0;
  return memcmp(a, b, (size_t)alen) == 0;
}

static incoming_call_t *call_list;
static neco_mutex call_mutex;
static int call_mutex_initialized;

__attribute__((unused))
static incoming_call_t *call_find(const char *call_id) {
  incoming_call_t *c;
  if (!call_id || !call_mutex_initialized) return NULL;
  neco_mutex_lock(&call_mutex);
  for (c = call_list; c; c = c->next)
    if (c->call_id && strcmp(c->call_id, call_id) == 0) break;
  neco_mutex_unlock(&call_mutex);
  return c;
}

/* Find call by Call-ID with mutex held; caller must unlock. Returns NULL with mutex released. */
static incoming_call_t *call_find_locked(const char *call_id) {
  incoming_call_t *c;
  if (!call_id || !call_mutex_initialized) return NULL;
  neco_mutex_lock(&call_mutex);
  for (c = call_list; c; c = c->next)
    if (c->call_id && strcmp(c->call_id, call_id) == 0) return c;
  neco_mutex_unlock(&call_mutex);
  return NULL;
}

/* Notify plugins of CALL.ANSWER (direction, call_id, source, destination). */
static void notify_call_answer(const char *direction, const char *call_id, const char *source, const char *destination) {
  size_t i;
  if (plugin_count() == 0) return;
  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "CALL.ANSWER")) break;
  }
  if (i >= plugin_count()) return;
  const char *argv[] = { direction ? direction : "", call_id ? call_id : "", source ? source : "", destination ? destination : "" };
  plugin_notify_event("CALL.ANSWER", 4, argv);
}

/* Notify plugins of CALL.HANGUP (call_id, source, destination, duration_seconds). */
static void notify_call_hangup(const char *call_id, const char *source, const char *destination, int duration_sec) {
  size_t i;
  if (plugin_count() == 0) return;
  for (i = 0; i < plugin_count(); i++) {
    if (plugin_has_event(plugin_name_at(i), "CALL.HANGUP")) break;
  }
  if (i >= plugin_count()) return;
  char dur_buf[32];
  snprintf(dur_buf, sizeof(dur_buf), "%d", duration_sec);
  const char *argv[] = { call_id ? call_id : "", source ? source : "", destination ? destination : "", dur_buf };
  plugin_notify_event("CALL.HANGUP", 4, argv);
}

/* Unlink and free call; expects call_mutex held. Emits CALL.HANGUP before free. */
static void call_remove_locked(incoming_call_t *call) {
  if (!call || !call_list) return;
  int duration = 0;
  if (call->answered && call->answered_at > 0)
    duration = (int)(time(NULL) - call->answered_at);
  notify_call_hangup(call->call_id, call->source_str, call->dest_str, duration);
  if (call_list == call) {
    call_list = call->next;
  } else {
    incoming_call_t *p = call_list;
    for (; p && p->next != call; p = p->next) ;
    if (p) p->next = call->next;
  }
  free(call->call_id);
  free(call->original_invite);
  free(call->source_str);
  free(call->dest_str);
  if (call->forks) {
    for (size_t i = 0; i < call->n_forks; i++)
      free(call->forks[i].ext_number);
    free(call->forks);
  }
  free(call);
}

__attribute__((unused))
static void call_remove(incoming_call_t *call) {
  if (!call || !call_mutex_initialized) return;
  neco_mutex_lock(&call_mutex);
  call_remove_locked(call);
  neco_mutex_unlock(&call_mutex);
}

/* Get one extension registration by trunk and number. Caller does not free. */
static ext_reg_t *get_ext_reg_by_number(const char *trunk_name, const char *number) {
  ext_reg_t *reg = NULL;
  time_t now = time(NULL);
  if (!reg_mutex_initialized || !trunk_name || !number) return NULL;
  neco_mutex_lock(&reg_mutex);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].trunk_name, trunk_name) != 0) continue;
    if (strcmp(reg_list[i].number, number) == 0) {
      reg = &reg_list[i];
      break;
    }
  }
  neco_mutex_unlock(&reg_mutex);
  return reg;
}

/* Fill ext_reg_t* array for extensions registered on trunk. *out (array of pointers) freed by caller. Returns count. */
static size_t get_ext_regs_for_trunk(const char *trunk_name, ext_reg_t ***out) {
  ext_reg_t **list = NULL;
  size_t n = 0;
  time_t now = time(NULL);
  if (!reg_mutex_initialized || !trunk_name || !out) return 0;
  *out = NULL;
  neco_mutex_lock(&reg_mutex);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].trunk_name, trunk_name) != 0) continue;
    ext_reg_t **new_list = (ext_reg_t **)realloc(list, (n + 1) * sizeof(ext_reg_t *));
    if (!new_list) break;
    list = new_list;
    list[n++] = &reg_list[i];
  }
  neco_mutex_unlock(&reg_mutex);
  *out = list;
  return n;
}

/* Fill ext_reg_t* array for an extension number (any trunk). *out freed by caller. Returns count. */
static size_t get_ext_regs_for_extension(const char *ext_number, ext_reg_t ***out) {
  ext_reg_t **list = NULL;
  size_t n = 0;
  time_t now = time(NULL);
  if (!reg_mutex_initialized || !ext_number || !out) return 0;
  *out = NULL;
  neco_mutex_lock(&reg_mutex);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].number, ext_number) != 0) continue;
    ext_reg_t **new_list = (ext_reg_t **)realloc(list, (n + 1) * sizeof(ext_reg_t *));
    if (!new_list) break;
    list = new_list;
    list[n++] = &reg_list[i];
  }
  neco_mutex_unlock(&reg_mutex);
  *out = list;
  return n;
}

/* Parse Contact URI string to host and port. Contact may be "sip:user@host:port" or "<sip:...>". Return 0 on success. */
static int contact_to_host_port(const char *contact, char *host, size_t host_size, char *port, size_t port_size) {
  const char *s = contact;
  if (!s || !host || host_size == 0 || !port || port_size == 0) return -1;
  while (*s == ' ' || *s == '\t') s++;
  if (*s == '<') s++;
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

static int verify_digest(const char *req_buf, size_t req_len, const char *method, const char *password,
    const char *expected_realm) {
  char *user = NULL, *realm = NULL, *nonce = NULL, *cnonce = NULL, *nc = NULL, *qop = NULL, *uri = NULL, *client_response = NULL;
  if (!sip_parse_authorization_digest(req_buf, req_len, &user, &realm, &nonce, &cnonce, &nc, &qop, &uri, &client_response))
    return 0;
  if (!user || !realm || !nonce || !uri || !client_response) {
    free(user); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(client_response);
    return 0;
  }
  if (strcmp(realm, expected_realm) != 0) {
    free(user); free(realm); free(nonce); free(cnonce); free(nc); free(qop); free(uri); free(client_response);
    return 0;
  }
  HASHHEX ha1, response_hex;
  digest_calc_ha1("MD5", user, realm, password, nonce, cnonce, ha1);
  HASHHEX hent = "";
  digest_calc_response(ha1, nonce, nc ? nc : "", cnonce ? cnonce : "", qop ? qop : "", method, uri, hent, response_hex);
  int ok = (strcasecmp((char *)response_hex, client_response) == 0);
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

/* Build SIP response. Caller frees returned buffer. *out_len set to length. */
static char *build_reply(const char *req_buf, size_t req_len, int code, int copy_contact, int add_wwa, size_t *out_len) {
  const char *reason = reason_phrase(code);
  const char *extra[2];
  size_t n_extra = 0;
  if (add_wwa) {
    extra[0] = build_www_authenticate();
    if (extra[0]) n_extra = 1;
  }
  char *resp = sip_build_response(req_buf, req_len, code, reason, copy_contact, n_extra ? extra : NULL, n_extra, out_len);
  if (add_wwa && extra[0]) free((void *)extra[0]);
  return resp;
}

static int sdp_rewrite_for_rtp_relay(upbx_config *cfg, const char *body, size_t body_len,
  const char *call_id_number, const char *call_id_host, int cseq, int call_direction,
  char **new_body_out, size_t *new_len_out);

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
  char user_buf[256];
  if (!sip_request_uri_user(req_buf, req_len, user_buf, sizeof(user_buf))) {
    if (!sip_header_uri_user(req_buf, req_len, "To", user_buf, sizeof(user_buf)))
      user_buf[0] = '\0';
  }
  const char *user = user_buf;
  if (!user[0]) {
    char *r = build_reply(req_buf, req_len, 400, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
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
    char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  config_extension *ext = get_extension_config(cfg, extension_num);
  if (!ext) {
    free(extension_num);
    char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  config_trunk *trunk = resolve_trunk_for_extension(cfg, extension_num, user);
  if (!trunk) {
    free(extension_num);
    char *r = build_reply(req_buf, req_len, 404, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }

  /* Plugin EXTENSION.REGISTER: can DENY, ALLOW (with optional custom data), or CONTINUE (built-in auth). */
  int plugin_allow = -1;
  char *plugin_custom = NULL;
  if (plugin_count() > 0)
    plugin_query_register(extension_num, trunk->name, user, &plugin_allow, &plugin_custom);
  if (plugin_allow == 0) {
    free(extension_num);
    free(plugin_custom);
    char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  if (plugin_allow != 1) {
    char *auth_user = NULL, *auth_stripped = NULL;
    if (!sip_parse_authorization_digest(req_buf, req_len, &auth_user, NULL, NULL, NULL, NULL, NULL, NULL, NULL) || !ext->secret) {
      char *r = build_reply(req_buf, req_len, 401, 0, 1, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      free(extension_num);
      free(auth_user);
      return;
    }
    if (auth_user) {
      const char *at2 = strchr(auth_user, '@');
      if (at2) {
        auth_stripped = malloc((size_t)(at2 - auth_user) + 1);
        if (auth_stripped) { memcpy(auth_stripped, auth_user, (size_t)(at2 - auth_user)); auth_stripped[at2 - auth_user] = '\0'; }
      } else
        auth_stripped = strdup(auth_user);
    }
    if (!auth_stripped || strcmp(auth_stripped, extension_num) != 0) {
      free(auth_user); free(auth_stripped); free(extension_num);
      char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return;
    }
    free(auth_user); free(auth_stripped);
    if (!verify_digest(req_buf, req_len, "REGISTER", ext->secret, AUTH_REALM)) {
      free(extension_num);
      char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return;
    }
  }

  if (!reg_mutex_initialized) {
    neco_mutex_init(&reg_mutex);
    reg_mutex_initialized = 1;
  }
  char *contact_val = get_contact_value(req_buf, req_len);
  neco_mutex_lock(&reg_mutex);
  for (size_t i = 0; i < reg_count; i++) {
    if (strcmp(reg_list[i].number, extension_num) == 0) {
      free(reg_list[i].trunk_name);
      free(reg_list[i].contact);
      free(reg_list[i].plugin_data);
      reg_list[i].trunk_name = strdup(trunk->name);
      reg_list[i].contact = contact_val ? contact_val : strdup("");
      reg_list[i].plugin_data = plugin_custom;
      reg_list[i].expires = time(NULL) + DEFAULT_EXPIRES;
      neco_mutex_unlock(&reg_mutex);
      if (!contact_val) contact_val = strdup("");
      free(extension_num);
      { char *r = build_reply(req_buf, req_len, 200, 1, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
      notify_extension_and_trunk_lists(cfg);
      return;
    }
  }
  if (reg_count >= reg_cap) {
    size_t newcap = reg_cap ? reg_cap * 2 : 8;
    ext_reg_t *p = realloc(reg_list, newcap * sizeof(ext_reg_t));
    if (!p) { neco_mutex_unlock(&reg_mutex); free(extension_num); free(plugin_custom); free(contact_val);
      char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return; }
    reg_list = p;
    reg_cap = newcap;
  }
  reg_list[reg_count].number = extension_num;
  reg_list[reg_count].trunk_name = strdup(trunk->name);
  reg_list[reg_count].contact = contact_val ? contact_val : strdup("");
  reg_list[reg_count].plugin_data = plugin_custom;
  reg_list[reg_count].expires = time(NULL) + DEFAULT_EXPIRES;
  reg_count++;
  neco_mutex_unlock(&reg_mutex);
  { char *r = build_reply(req_buf, req_len, 200, 1, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
  notify_extension_and_trunk_lists(cfg);
}

static const char *reason_phrase(int code) {
  switch (code) {
    case 100: return "Trying";
    case 200: return "OK";
    case 400: return "Bad Request";
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

/* Get CSeq number from request (first token of CSeq header). */
static int get_cseq_number(const char *buf, size_t len) {
  const char *val;
  size_t val_len;
  if (!sip_header_get(buf, len, "CSeq", &val, &val_len) || val_len == 0) return 0;
  return atoi(val);
}

/* Route INVITE to plugin-provided targets (SIP URIs). Sends INVITE to each, then 100 Trying to caller. */
__attribute__((unused))
static void handle_invite_route_to_targets(upbx_config *cfg, const char *req_buf, size_t req_len, sip_send_ctx *ctx, char **targets, size_t n_targets) {
  for (size_t i = 0; i < n_targets; i++) {
    if (!targets[i] || !targets[i][0]) continue;
    char host[256], port[32];
    if (contact_to_host_port(targets[i], host, sizeof(host), port, sizeof(port)) != 0) continue;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) continue;
    char *inv = sip_request_replace_uri(req_buf, req_len, NULL, host, port);
    if (inv) {
      udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, inv, strlen(inv));
      free(inv);
    }
    freeaddrinfo(res);
  }
  { char *r = build_reply(req_buf, req_len, 100, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
}

static int parse_listen_addr(const char *addr, char *host, size_t host_size, char *port, size_t port_size);

/* Overflow timer coroutine: after timeout, apply strategy (busy/add/redirect) if not answered. */
static void overflow_timer_coro(int argc, void *argv[]) {
  incoming_call_t *call = (incoming_call_t *)argv[0];
  upbx_config *cfg = (upbx_config *)argv[1];
  int sockfd = (int)(intptr_t)argv[2];
  if (argc < 3 || !call || !cfg) return;
  if (!call->trunk) return; /* ext-to-ext calls have no overflow */
  int timeout_sec = call->trunk->overflow_timeout;
  if (timeout_sec <= 0) return;
  int64_t deadline = neco_now() + (int64_t)timeout_sec * 1000000000;
  for (;;) {
    neco_sleep(500 * 1000000); /* 500ms tick */
    if (neco_now() >= deadline) break;
    neco_mutex_lock(&call_mutex);
    int done = call->answered || call->overflow_done;
    neco_mutex_unlock(&call_mutex);
    if (done) return;
  }
  neco_mutex_lock(&call_mutex);
  if (call->answered || call->overflow_done) {
    neco_mutex_unlock(&call_mutex);
    return;
  }
  call->overflow_done = 1;
  const char *strategy = call->trunk->overflow_strategy ? call->trunk->overflow_strategy : "none";
  int do_busy = 0, do_include = 0, do_redirect = 0;
  if (strcasecmp(strategy, "busy") == 0) do_busy = 1;
  else if (strcasecmp(strategy, "include") == 0 && call->trunk->overflow_target && call->trunk->overflow_target[0]) do_include = 1;
  else if (strcasecmp(strategy, "redirect") == 0 && call->trunk->overflow_target && call->trunk->overflow_target[0]) do_redirect = 1;
  /* Copy fields we need after unlock to avoid use-after-free if response handler removes call */
  char *orig_invite = call->original_invite ? malloc(call->original_invite_len + 1) : NULL;
  size_t orig_len = call->original_invite_len;
  struct sockaddr_storage caller_peer;
  socklen_t caller_peerlen = call->caller_peerlen;
  char trunk_name[64], overflow_target[64];
  char *call_id_copy = call->call_id ? strdup(call->call_id) : NULL;
  trunk_name[0] = overflow_target[0] = '\0';
  if (call->trunk && call->trunk->name) strncpy(trunk_name, call->trunk->name, sizeof(trunk_name) - 1);
  if (call->trunk && call->trunk->overflow_target) strncpy(overflow_target, call->trunk->overflow_target, sizeof(overflow_target) - 1);
  if (orig_invite && call->original_invite) memcpy(orig_invite, call->original_invite, orig_len + 1);
  memcpy(&caller_peer, &call->caller_peer, sizeof(caller_peer));
  neco_mutex_unlock(&call_mutex);

  if (do_busy) {
    if (orig_invite && orig_len > 0) {
      char *resp = build_reply(orig_invite, orig_len, 486, 0, 0, NULL);
      if (resp) {
        udp_send_to(sockfd, (struct sockaddr *)&caller_peer, caller_peerlen, resp, strlen(resp));
        free(resp);
      }
    }
    free(orig_invite);
    if (call_id_copy) {
      incoming_call_t *c = call_find_locked(call_id_copy);
      if (c) { call_remove_locked(c); neco_mutex_unlock(&call_mutex); }
      free(call_id_copy);
    }
    return;
  }

  if (do_redirect) {
    /* Send CANCEL to each fork */
    for (size_t i = 0; i < call->n_forks; i++) {
      /* Build CANCEL (same Via, Call-ID, From, To, CSeq method CANCEL) - simplified: just send CANCEL request */
      (void)i;
      /* We don't have a simple CANCEL builder; skip CANCEL for now and just send INVITE to overflow_target */
    }
  }

  if (do_include || do_redirect) {
    ext_reg_t *overflow_reg = get_ext_reg_by_number(trunk_name, overflow_target);
    if (overflow_reg && orig_invite && orig_len > 0) {
      char host[256], port[32];
      if (contact_to_host_port(overflow_reg->contact, host, sizeof(host), port, sizeof(port)) == 0) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(host, port, &hints, &res) == 0 && res) {
          const char *call_id_val;
          size_t call_id_len;
          sip_header_get(orig_invite, orig_len, "Call-ID", &call_id_val, &call_id_len);
          char cid[128];
          if (call_id_len > 0 && call_id_len < sizeof(cid)) { memcpy(cid, call_id_val, call_id_len); cid[call_id_len] = '\0'; } else cid[0] = '\0';
          int cseq = get_cseq_number(orig_invite, orig_len);
          char *inv = sip_request_replace_uri(orig_invite, orig_len, overflow_reg->number, host, port);
          if (inv) {
            size_t inv_len = strlen(inv);
            char via_host[256], via_port[32];
            const char *listen = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
            if (parse_listen_addr(listen, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0) {
              char *inv2 = sip_request_add_via(inv, inv_len, via_host, via_port);
              free(inv);
              inv = inv2;
              if (inv) inv_len = strlen(inv);
            }
            if (inv) {
              const char *body;
              size_t body_len;
              char *final_inv = inv;
              size_t final_len = inv_len;
              if (sip_request_get_body(inv, inv_len, &body, &body_len) && body_len > 0) {
                char *new_body = NULL;
                size_t new_body_len = 0;
                if (sdp_rewrite_for_rtp_relay(cfg, body, body_len, cid, "", cseq, RTP_RELAY_CALL_INCOMING, &new_body, &new_body_len) == 0 && new_body) {
                  char *inv3 = sip_request_replace_body(inv, inv_len, new_body, new_body_len);
                  free(new_body);
                  if (inv3) { free(inv); final_inv = inv3; final_len = strlen(inv3); }
                }
              }
              udp_send_to(sockfd, res->ai_addr, res->ai_addrlen, final_inv, final_len);
              free(final_inv);
            }
          }
          freeaddrinfo(res);
        }
      }
    }
    free(orig_invite);
    /* for both include and redirect we keep the call so we can forward 2xx from overflow target */
  } else {
    free(orig_invite);
  }
  free(call_id_copy);
}

/* Fork INVITE to a list of extension registrations; create call, send 100. trunk may be NULL (ext-to-ext). Caller frees exts. */
static void fork_invite_to_extension_regs(upbx_config *cfg, const char *req_buf, size_t req_len, sip_send_ctx *ctx,
  ext_reg_t **exts, size_t n_ext, config_trunk *trunk, const char *source_str) {
  char via_host[256], via_port[32];
  const char *listen = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  if (parse_listen_addr(listen, via_host, sizeof(via_host), via_port, sizeof(via_port)) != 0) {
    char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  const char *call_id_val;
  size_t call_id_len;
  sip_header_get(req_buf, req_len, "Call-ID", &call_id_val, &call_id_len);
  char call_id_buf[256];
  if (call_id_len > 0 && call_id_len < sizeof(call_id_buf)) { memcpy(call_id_buf, call_id_val, call_id_len); call_id_buf[call_id_len] = '\0'; } else call_id_buf[0] = '\0';
  incoming_call_t *call = malloc(sizeof(incoming_call_t));
  if (!call) {
    char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  memset(call, 0, sizeof(*call));
  call->call_id = call_id_buf[0] ? strdup(call_id_buf) : NULL;
  call->sockfd = ctx->sockfd;
  memcpy(&call->caller_peer, &ctx->peer, sizeof(call->caller_peer));
  call->caller_peerlen = ctx->peerlen;
  call->trunk = trunk;
  call->original_invite = malloc(req_len + 1);
  if (call->original_invite) {
    memcpy(call->original_invite, req_buf, req_len);
    call->original_invite[req_len] = '\0';
    call->original_invite_len = req_len;
  }
  call->forks = NULL;
  call->n_forks = 0;
  call->source_str = source_str ? strdup(source_str) : NULL;
  call->dest_str = NULL;
  call->answered_at = 0;

  if (!call_mutex_initialized) {
    neco_mutex_init(&call_mutex);
    call_mutex_initialized = 1;
  }

  int cseq = get_cseq_number(req_buf, req_len);
  for (size_t i = 0; i < n_ext; i++) {
    char host[256], port[32];
    if (contact_to_host_port(exts[i]->contact, host, sizeof(host), port, sizeof(port)) != 0)
      continue;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res)
      continue;
    char *inv = sip_request_replace_uri(req_buf, req_len, exts[i]->number, host, port);
    if (inv) {
      size_t inv_len = strlen(inv);
      char *inv2 = sip_request_add_via(inv, inv_len, via_host, via_port);
      free(inv);
      inv = inv2;
      if (inv) inv_len = strlen(inv);
    }
    if (inv) {
      const char *body;
      size_t body_len;
      if (sip_request_get_body(inv, strlen(inv), &body, &body_len) && body_len > 0) {
        char *new_body = NULL;
        size_t new_body_len = 0;
        if (sdp_rewrite_for_rtp_relay(cfg, body, body_len, call_id_buf, "", cseq, RTP_RELAY_CALL_INCOMING, &new_body, &new_body_len) == 0 && new_body) {
          char *inv3 = sip_request_replace_body(inv, strlen(inv), new_body, new_body_len);
          free(new_body);
          if (inv3) { free(inv); inv = inv3; }
        }
      }
      if (inv) {
        size_t send_len = strlen(inv);
        udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, inv, send_len);
        fork_peer_t *new_forks = realloc(call->forks, (call->n_forks + 1) * sizeof(fork_peer_t));
        if (new_forks) {
          call->forks = new_forks;
          memcpy(&call->forks[call->n_forks].peer, res->ai_addr, res->ai_addrlen);
          call->forks[call->n_forks].peerlen = res->ai_addrlen;
          call->forks[call->n_forks].ext_number = exts[i]->number ? strdup(exts[i]->number) : NULL;
          call->n_forks++;
        }
      }
      free(inv);
    }
    freeaddrinfo(res);
  }

  neco_mutex_lock(&call_mutex);
  call->next = call_list;
  call_list = call;
  neco_mutex_unlock(&call_mutex);

  if (trunk && trunk->overflow_timeout > 0 && trunk->overflow_strategy && trunk->overflow_strategy[0] &&
      strcasecmp(trunk->overflow_strategy, "none") != 0) {
    neco_start(overflow_timer_coro, 3, call, cfg, (void *)(intptr_t)ctx->sockfd);
  } else {
    call->overflow_done = 1;
  }

  { char *r = build_reply(req_buf, req_len, 100, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
}

/* Incoming INVITE: DID matches trunk → fork to extensions. If override_ext_numbers non-NULL, ring only those (on this trunk). */
static void handle_invite_incoming(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx, const char *did,
  const char **override_ext_numbers, size_t n_override) {
  config_trunk *trunk = find_trunk_by_did(cfg, did);
  if (!trunk) {
    char *r = build_reply(buf, len, 404, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  ext_reg_t **exts = NULL;
  size_t n_ext = 0;
  if (override_ext_numbers && n_override > 0) {
    exts = (ext_reg_t **)malloc(n_override * sizeof(ext_reg_t *));
    if (exts) {
      for (size_t k = 0; k < n_override; k++) {
        ext_reg_t *r = get_ext_reg_by_number(trunk->name, override_ext_numbers[k]);
        if (r) exts[n_ext++] = r;
      }
      if (n_ext == 0) { free(exts); exts = NULL; }
    }
  } else
    n_ext = get_ext_regs_for_trunk(trunk->name, &exts);
  if (n_ext == 0 || !exts) {
    free(exts);
    char *r = build_reply(buf, len, 480, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  fork_invite_to_extension_regs(cfg, buf, len, ctx, exts, n_ext, trunk, did);
  free(exts);
}

/* Outgoing INVITE: from registered extension → forward to that extension's trunk. Trunk rewrite rules are always applied when configured. */
static void handle_invite_outgoing(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx, const char *from_user) {
  const char *at = strchr(from_user, '@');
  size_t ext_len = at ? (size_t)(at - from_user) : strlen(from_user);
  char *ext_num = malloc(ext_len + 1);
  if (!ext_num) {
    char *r = build_reply(buf, len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  memcpy(ext_num, from_user, ext_len);
  ext_num[ext_len] = '\0';
  ext_reg_t *reg = NULL;
  if (!reg_mutex_initialized) {
    free(ext_num);
    char *r = build_reply(buf, len, 404, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  neco_mutex_lock(&reg_mutex);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= time(NULL)) continue;
    if (strcmp(reg_list[i].number, ext_num) == 0) {
      reg = &reg_list[i];
      break;
    }
  }
  neco_mutex_unlock(&reg_mutex);
  free(ext_num);
  if (!reg) {
    char *r = build_reply(buf, len, 404, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  config_trunk *trunk = get_trunk_config(cfg, reg->trunk_name);
  if (!trunk || !trunk->host) {
    char *r = build_reply(buf, len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  const char *send_buf = buf;
  size_t send_len = len;
  char *rewritten_buf = NULL;
  if (trunk->rewrite_regex && trunk->rewrite_count > 0) {
    char req_user[256], req_host[256], req_port[32];
    if (sip_request_uri_user(buf, len, req_user, sizeof(req_user)) &&
        sip_request_uri_host_port(buf, len, req_host, sizeof(req_host), req_port, sizeof(req_port))) {
      char rewritten[256];
      apply_trunk_rewrites(trunk, req_user, rewritten, sizeof(rewritten));
      rewritten_buf = sip_request_replace_uri(buf, len, rewritten, req_host, req_port);
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
    char *r = build_reply(buf, len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  log_trace("sip_server: sending %zu bytes to trunk %s (%s:%s)", send_len, trunk->name, trunk->host, port);
  log_hexdump_trace(send_buf, send_len);
  udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, send_buf, send_len);
  free(rewritten_buf);
  freeaddrinfo(res);
  { char *r = build_reply(buf, len, 100, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
}

/* Dispatch INVITE: CALL.DIALIN / CALL.DIALOUT plugin events, then incoming (DID) or outgoing (from extension). */
static void handle_invite(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx) {
  char to_user_buf[256], from_user_buf[256], call_id_buf[256];
  to_user_buf[0] = from_user_buf[0] = call_id_buf[0] = '\0';
  sip_request_uri_user(buf, len, to_user_buf, sizeof(to_user_buf));
  if (!to_user_buf[0]) sip_header_uri_user(buf, len, "To", to_user_buf, sizeof(to_user_buf));
  sip_header_uri_user(buf, len, "From", from_user_buf, sizeof(from_user_buf));
  const char *call_id_val;
  size_t call_id_len;
  if (sip_header_get(buf, len, "Call-ID", &call_id_val, &call_id_len) && call_id_len < sizeof(call_id_buf)) {
    memcpy(call_id_buf, call_id_val, call_id_len);
    call_id_buf[call_id_len] = '\0';
  }
  const char *to_user = to_user_buf;
  const char *from_user = from_user_buf;
  const char *call_id = call_id_buf;

  if (to_user[0] && find_trunk_by_did(cfg, to_user)) {
    config_trunk *trunk = find_trunk_by_did(cfg, to_user);
    ext_reg_t **exts = NULL;
    size_t n_ext = get_ext_regs_for_trunk(trunk->name, &exts);
    if (plugin_count() > 0 && n_ext > 0 && exts) {
      const char **ext_numbers = (const char **)malloc(n_ext * sizeof(const char *));
      if (ext_numbers) {
        for (size_t i = 0; i < n_ext; i++) ext_numbers[i] = exts[i]->number;
        int action = 0;
        int reject_code = 403;
        char **override_targets = NULL;
        size_t n_override = 0;
        plugin_query_dialin(trunk->name, to_user, ext_numbers, n_ext, call_id,
          &action, &reject_code, &override_targets, &n_override);
        free(ext_numbers);
        if (action == 1) {
          free(exts);
          { char *r = build_reply(buf, len, reject_code, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
          return;
        }
        if (action == 2 && override_targets && n_override > 0) {
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

  if (from_user[0] && get_extension_config(cfg, from_user)) {
    const char *at = strchr(from_user, '@');
    size_t ext_len = at ? (size_t)(at - from_user) : strlen(from_user);
    char *ext_num = (char *)malloc(ext_len + 1);
    if (!ext_num) {
      char *r = build_reply(buf, len, 503, 0, 0, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return;
    }
    memcpy(ext_num, from_user, ext_len);
    ext_num[ext_len] = '\0';
    if (to_user[0] && get_extension_config(cfg, to_user) && strcmp(ext_num, to_user) != 0) {
      ext_reg_t **exts = NULL;
      size_t n_ext = get_ext_regs_for_extension(to_user, &exts);
      if (n_ext > 0 && exts) {
        fork_invite_to_extension_regs(cfg, buf, len, ctx, exts, n_ext, NULL, to_user);
        free(exts);
        free(ext_num);
        return;
      }
      free(exts);
    }
    ext_reg_t *reg = NULL;
    if (reg_mutex_initialized) {
      neco_mutex_lock(&reg_mutex);
      for (size_t i = 0; i < reg_count; i++) {
        if (reg_list[i].expires <= time(NULL)) continue;
        if (strcmp(reg_list[i].number, ext_num) == 0) { reg = &reg_list[i]; break; }
      }
      neco_mutex_unlock(&reg_mutex);
    }
    const char *trunk_name = reg && reg->trunk_name ? reg->trunk_name : "";
    const char *destination = to_user[0] ? to_user : "";
    char *target_override = NULL;
    int dialout_action = 0;
    int reject_code = 403;
    if (plugin_count() > 0 && !is_emergency_number(cfg, destination)) {
      plugin_query_dialout(ext_num, trunk_name, destination, call_id, &dialout_action, &reject_code, &target_override);
    }
    if (dialout_action == 1) {
      free(ext_num);
      { char *r = build_reply(buf, len, reject_code, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
      free(target_override);
      return;
    }
    const char *cur_buf = buf;
    size_t cur_len = len;
    char *override_buf = NULL;
    if (dialout_action == 2 && target_override && target_override[0]) {
      char req_host[256], req_port[32];
      if (sip_request_uri_host_port(buf, len, req_host, sizeof(req_host), req_port, sizeof(req_port))) {
        override_buf = sip_request_replace_uri(buf, len, target_override, req_host, req_port);
        if (override_buf) { cur_buf = override_buf; cur_len = strlen(override_buf); }
      }
      free(target_override);
    } else
      free(target_override);
    free(ext_num);
    handle_invite_outgoing(cfg, cur_buf, cur_len, ctx, from_user);
    free(override_buf);
    return;
  }
  if (from_user[0]) {
    const char *at = strchr(from_user, '@');
    size_t ext_len = at ? (size_t)(at - from_user) : strlen(from_user);
    char *ext_num = (char *)malloc(ext_len + 1);
    if (ext_num) {
      memcpy(ext_num, from_user, ext_len);
      ext_num[ext_len] = '\0';
      if (get_extension_config(cfg, ext_num)) {
        free(ext_num);
        handle_invite_outgoing(cfg, buf, len, ctx, from_user);
        return;
      }
      free(ext_num);
    }
  }
  { char *r = build_reply(buf, len, 404, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
}

/* Forward a SIP response from a forked leg to the caller (trunk). Strip our Via (first) before sending. */
static void handle_sip_response(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx) {
  (void)cfg;
  const char *call_id_val;
  size_t call_id_len;
  if (!sip_header_get(buf, len, "Call-ID", &call_id_val, &call_id_len) || call_id_len == 0) return;
  char call_id_buf[256];
  if (call_id_len >= sizeof(call_id_buf)) return;
  memcpy(call_id_buf, call_id_val, call_id_len);
  call_id_buf[call_id_len] = '\0';
  incoming_call_t *call = call_find_locked(call_id_buf);
  if (!call) return;
  char *forward = sip_response_strip_first_via(buf, len);
  if (!forward) { neco_mutex_unlock(&call_mutex); return; }
  size_t forward_len = strlen(forward);
  udp_send_to(ctx->sockfd, (struct sockaddr *)&call->caller_peer, call->caller_peerlen, forward, forward_len);
  free(forward);

  int code = sip_response_status_code(buf, len);
  int remove = 0;
  if (code >= 200 && code < 300) {
    call->answered = 1;
    call->answered_at = time(NULL);
    for (size_t f = 0; f < call->n_forks; f++) {
      if (sockaddr_match(&ctx->peer, ctx->peerlen, &call->forks[f].peer, call->forks[f].peerlen)) {
        if (call->forks[f].ext_number) {
          free(call->dest_str);
          call->dest_str = strdup(call->forks[f].ext_number);
        }
        break;
      }
    }
    notify_call_answer("dialin", call->call_id, call->source_str, call->dest_str);
    remove = 1;
  } else if (code >= 600) {
    remove = 1;
  }
  if (remove)
    call_remove_locked(call);
  neco_mutex_unlock(&call_mutex);
}

/* One UDP datagram: peer address + message (flexible array). Caller frees. */
typedef struct {
  struct sockaddr_storage peer;
  socklen_t peerlen;
  size_t len;
  char buf[];
} udp_msg_t;

/* Return true if buf[0..len-1] looks like a SIP message so libosip2 parse is safe. */
static bool looks_like_sip(const char *buf, size_t len) {
  log_trace("%s", __func__);
  if (len < 12)
    return false;
  /* Must end headers with \r\n\r\n so parser doesn't run off. */
  size_t max = len < SIP_MAX_HEADERS ? len : SIP_MAX_HEADERS;
  for (size_t i = 0; i + 3 < max; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
      return true;
  }
  return false;
}

/* Handle one UDP datagram (SIP request or response). */
static void sip_server_udp_msg(int argc, void *argv[]) {
  log_trace("%s", __func__);
  upbx_config *cfg = (upbx_config *)argv[0];
  udp_msg_t *msg = (udp_msg_t *)argv[1];
  int sockfd = (int)(intptr_t)argv[2];
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
  sip_fixup_for_parse(buf, &len, msg->len + 1);
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
    handle_register(buf, len, cfg, &ctx);
  } else if (method_len == 6 && strncasecmp(method, "INVITE", 6) == 0) {
    handle_invite(cfg, buf, len, &ctx);
  } else {
    char *r = build_reply(buf, len, 503, 0, 0, NULL);
    if (r) { send_response_buf(&ctx, r, strlen(r)); free(r); }
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

/* Resolve host (IP or name) to in_addr; return 0 on success. */
static int resolve_to_in_addr(const char *host, struct in_addr *out) {
  struct in_addr a;
  if (inet_pton(AF_INET, host, &a) == 1) {
    *out = a;
    return 0;
  }
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res)
    return -1;
  struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
  out->s_addr = sin->sin_addr.s_addr;
  freeaddrinfo(res);
  return 0;
}

/* Minimal SDP rewrite for RTP relay: parse line-by-line, rewrite c= and m= port. */
static int sdp_rewrite_for_rtp_relay(upbx_config *cfg, const char *body, size_t body_len,
  const char *call_id_number, const char *call_id_host, int cseq, int call_direction,
  char **new_body_out, size_t *new_len_out) {
  char adv_host[256], adv_port[32];
  if (parse_listen_addr(cfg->listen ? cfg->listen : "0.0.0.0:5060", adv_host, sizeof(adv_host), adv_port, sizeof(adv_port)) != 0)
    return -1;
  struct in_addr advertise_addr, bind_addr;
  if (resolve_to_in_addr(adv_host, &advertise_addr) != 0) return -1;
  if (advertise_addr.s_addr == 0 || strcmp(adv_host, "0.0.0.0") == 0) return -1;
  bind_addr.s_addr = INADDR_ANY;
  char advertise_str[64];
  inet_ntop(AF_INET, &advertise_addr, advertise_str, sizeof(advertise_str));

  size_t cap = body_len + 4096;
  char *out = malloc(cap);
  if (!out) return -1;
  size_t used = 0;
  const char *p = body;
  const char *end = body + body_len;
  int session_c_set = 0;
  char session_c_line[256];
  int session_c_output = 0;
  int media_no = 0;
  int next_c_is_media = 0;
  int rewrite_port = -1;
  int rewrite_c = 0;

  while (p < end) {
    const char *line_start = p;
    while (p < end && *p != '\r' && *p != '\n') p++;
    size_t line_len = (size_t)(p - line_start);
    if (line_len == 0) {
      if (used + 2 > cap) break;
      out[used++] = '\r'; out[used++] = '\n';
      if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2; else if (p < end) p++;
      continue;
    }
    if (line_len >= 2 && line_start[0] == 'c' && line_start[1] == '=') {
      if (!session_c_set) {
        session_c_set = 1;
        size_t n = line_len < (sizeof(session_c_line) - 1) ? line_len : sizeof(session_c_line) - 1;
        memcpy(session_c_line, line_start, n); session_c_line[n] = '\0';
        if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2; else if (p < end) p++;
        continue;
      }
      if (next_c_is_media && rewrite_c) {
        if (used + 32 > cap) break;
        int n = snprintf(out + used, cap - used, "c=IN IP4 %s\r\n", advertise_str);
        if (n > 0) used += (size_t)n;
        next_c_is_media = 0;
      } else {
        if (used + line_len + 2 > cap) break;
        memcpy(out + used, line_start, line_len); used += line_len;
        out[used++] = '\r'; out[used++] = '\n';
      }
    } else if (line_len >= 2 && line_start[0] == 'm' && line_start[1] == '=') {
      const char *m_rest = line_start + 2;
      while (m_rest < line_start + line_len && (*m_rest == ' ' || *m_rest == '\t')) m_rest++;
      const char *port_start = m_rest;
      while (m_rest < line_start + line_len && *m_rest != ' ' && *m_rest != '\t') m_rest++;
      int remote_port = atoi(port_start);
      const char *proto_start = m_rest;
      while (proto_start < line_start + line_len && (*proto_start == ' ' || *proto_start == '\t')) proto_start++;
      int is_rtp = (proto_start + 4 <= line_start + line_len && strncasecmp(proto_start, "RTP/", 4) == 0);
      if (is_rtp && remote_port > 0 && remote_port <= 65535) {
        const char *c_addr = (session_c_set && strncmp(session_c_line, "c=IN IP4 ", 9) == 0) ? session_c_line + 9 : NULL;
        while (c_addr && *c_addr == ' ') c_addr++;
        if (c_addr && *c_addr && strcmp(c_addr, "0.0.0.0") != 0) {
          struct in_addr remote_addr;
          if (resolve_to_in_addr(c_addr, &remote_addr) == 0) {
            int local_port = 0;
            if (rtp_relay_start_fwd(cfg, call_id_number ? call_id_number : "", call_id_host ? call_id_host : "",
                  RTP_RELAY_DIR_INCOMING, call_direction, media_no,
                  bind_addr, &local_port, remote_addr, remote_port, cseq) == 0) {
              rewrite_port = local_port;
              next_c_is_media = 1;
              rewrite_c = 1;
            }
          }
        }
      }
      if (rewrite_port >= 0 && is_rtp) {
        if (!session_c_output && used + 32 <= cap) {
          int n = snprintf(out + used, cap - used, "c=IN IP4 %s\r\n", advertise_str);
          if (n > 0) { used += (size_t)n; session_c_output = 1; }
        }
        if (used + 64 > cap) break;
        size_t pre = (size_t)(port_start - line_start);
        int n = snprintf(out + used, cap - used, "%.*s%d", (int)pre, line_start, rewrite_port);
        if (n > 0) {
          used += (size_t)n;
          const char *rest = port_start;
          while (rest < line_start + line_len && *rest >= '0' && *rest <= '9') rest++;
          size_t rest_len = (size_t)((line_start + line_len) - rest);
          if (used + rest_len + 2 <= cap) { memcpy(out + used, rest, rest_len); used += rest_len; }
        }
        out[used++] = '\r'; out[used++] = '\n';
        rewrite_port = -1;
      } else {
        if (used + line_len + 2 > cap) break;
        memcpy(out + used, line_start, line_len); used += line_len;
        out[used++] = '\r'; out[used++] = '\n';
      }
      media_no++;
    } else {
      if (used + line_len + 2 > cap) break;
      memcpy(out + used, line_start, line_len); used += line_len;
      out[used++] = '\r'; out[used++] = '\n';
    }
    if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2; else if (p < end) p++;
  }

  *new_body_out = out;
  *new_len_out = used;
  return 0;
}

/* Create and bind UDP socket; return fd or -1. */
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
  if (ret != 0 || !res) return -1;
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
  {
    bool old;
    if (neco_setnonblock(fd, true, &old) != 0) {
      close(fd);
      return -1;
    }
  }
  return fd;
}

static void sip_server_main(int argc, void *argv[]) {
  log_trace("%s", __func__);
  upbx_config *cfg = (upbx_config *)argv[0];
  const char *listen_addr;
  int sockfd;
  char buf[SIP_READ_BUF_SIZE];
  struct sockaddr_storage peer;
  socklen_t peerlen;
  ssize_t n;

  if (argc < 1 || !cfg) {
    log_error("sip_server_main: no config");
    return;
  }
  if (rtp_relay_init(cfg) != 0)
    log_error("rtp_relay_init failed");
  else
    neco_start(rtp_relay_coro, 1, cfg);
  listen_addr = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  log_info("SIP binding to %s", listen_addr);
  sockfd = udp_bind(listen_addr);
  if (sockfd < 0) {
    log_error("sip_server_main: UDP bind %s failed", listen_addr);
    return;
  }
  log_info("SIP listening on UDP %s", listen_addr);
  if (cfg->trunk_count > 0)
    log_info("trunk registration started (%zu trunk(s))", cfg->trunk_count);
  notify_extension_and_trunk_lists(cfg);
  if (cfg->trunk_count > 0)
    neco_start(trunk_reg_loop, 1, cfg);
  for (;;) {
    if (neco_wait(sockfd, NECO_WAIT_READ) != 0)
      continue;
    peerlen = sizeof(peer);
    n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
    if (n <= 0 || (size_t)n > SIP_READ_BUF_SIZE - 1)
      continue;
    udp_msg_t *msg = malloc(sizeof(udp_msg_t) + (size_t)n + 1);
    if (!msg) continue;
    memcpy(&msg->peer, &peer, sizeof(msg->peer));
    msg->peerlen = peerlen;
    msg->len = (size_t)n;
    memcpy(msg->buf, buf, (size_t)n);
    msg->buf[n] = '\0';
    neco_start(sip_server_udp_msg, 3, cfg, msg, (void *)(intptr_t)sockfd);
  }
}

/* Root coroutine: start sip_server_main then sleep forever so the scheduler runs it (bluebox pattern). */
void daemon_root(int argc, void *argv[]) {
  log_trace("%s", __func__);
  upbx_config *cfg = (upbx_config *)argv[0];
  if (argc < 1 || !cfg)
    return;
  neco_start(sip_server_main, 1, cfg);
  for (;;)
    neco_sleep(3600 * (int64_t)1000000000); /* 1 hour, like bluebox's NECO_HOUR */
}
