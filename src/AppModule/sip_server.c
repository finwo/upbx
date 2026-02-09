/*
 * SIP server: listen on UDP, receive datagrams, parse SIP with minimal parser (no libosip2),
 * handle REGISTER (extension auth, registration store) and INVITE (call routing).
 * Single-threaded: select() loop and protothreads (pt.h); UDP sockets are non-blocking.
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

#include "pt.h"
#include "socket_util.h"
#include "AppModule/rtp_relay.h"
#include "rxi/log.h"
#include "config.h"
#include "AppModule/plugin.h"
#include "AppModule/sip_server.h"
#include "AppModule/sip_hexdump.h"
#include "AppModule/trunk_reg.h"
#include "AppModule/sip_parse.h"
#include "AppModule/sdp_parse.h"
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

/* Match siproxd auth.c: without qop use RFC 2069 response = MD5(HA1:nonce:HA2); with qop use RFC 2617. */
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
  if (qop && *qop) {
    /* RFC 2617 with qop: request-digest = MD5(HA1:nonce:nc:cnonce:qop:HA2) */
    if (nc) MD5_Update(&ctx, (const unsigned char *)nc, strlen(nc));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (cnonce) MD5_Update(&ctx, (const unsigned char *)cnonce, strlen(cnonce));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    MD5_Update(&ctx, (const unsigned char *)qop, strlen(qop));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
  }
  /* else RFC 2069: request-digest = MD5(HA1:nonce:HA2) — no nc/cnonce/qop */
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
  char *number;       /* Extension number (e.g. "206") for config lookup */
  char *uri_user;     /* Original username from REGISTER (e.g. "206%40finwo") for Request-URI in INVITE */
  char *trunk_name;
  char *contact;
  char *plugin_data;  /* Optional custom data from plugin ALLOW (e.g. external auth token) */
  time_t expires;
} ext_reg_t;

static ext_reg_t *reg_list;
static size_t reg_count;
static size_t reg_cap;
static int reg_list_ready;
static int reg_list_notify_pending;  /* set by handle_register; drained in main loop */

/* Address clients used to reach us (from Request-URI of REGISTER). Used for Via/SDP when advertise not in config. */
static char learned_advertise_host[256];
static char learned_advertise_port[32];

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
  if (!reg_list_ready || !ext_number || !reg_list) return "";
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].number, ext_number) == 0)
      return reg_list[i].trunk_name ? reg_list[i].trunk_name : "";
  }
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
            if (reg_list) {
              for (j = 0; j < reg_count; j++) {
                if (reg_list[j].expires <= now) continue;
                if (strcmp(reg_list[j].trunk_name, t->name) != 0) continue;
                if (exts_strs[i][0]) strcat(exts_strs[i], ",");
                if (reg_list[j].number) strcat(exts_strs[i], reg_list[j].number);
              }
            }
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
  char *caller_via;   /* first Via from caller (for response masquerading) */
  char *source_str;   /* DID or caller extension (for CALL.ANSWER/HANGUP) */
  char *dest_str;     /* answering extension (set on 2xx) */
  time_t answered_at; /* when 2xx was received (for duration) */
  time_t created_at;  /* when call was created (for overflow timeout) */
  /* RTP relay: ports we advertise to caller in 200 OK (OUTGOING legs); set when rewriting offer before fork */
  uint16_t rtp_caller_ports[8];
  size_t n_rtp_caller_ports;
} incoming_call_t;

static int sockaddr_match(const struct sockaddr_storage *a, socklen_t alen, const struct sockaddr_storage *b, socklen_t blen) {
  if (alen != blen) return 0;
  return memcmp(a, b, (size_t)alen) == 0;
}

static incoming_call_t *call_list;

__attribute__((unused))
static incoming_call_t *call_find(const char *call_id) {
  incoming_call_t *c;
  if (!call_id) return NULL;
  for (c = call_list; c; c = c->next)
    if (c->call_id && strcmp(c->call_id, call_id) == 0) return c;
  return c;
}

/* Find call by Call-ID. Single-threaded: no lock. */
static incoming_call_t *call_find_locked(const char *call_id) {
  incoming_call_t *c;
  if (!call_id) return NULL;
  for (c = call_list; c; c = c->next)
    if (c->call_id && strcmp(c->call_id, call_id) == 0) return c;
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

/* Unlink and free call. Emits CALL.HANGUP before free. */
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
  free(call->caller_via);
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
  if (!call) return;
  call_remove_locked(call);
}

/* Get one extension registration by trunk and number. Caller does not free. */
static ext_reg_t *get_ext_reg_by_number(const char *trunk_name, const char *number) {
  ext_reg_t *reg = NULL;
  time_t now = time(NULL);
  if (!reg_list_ready || !reg_list || !trunk_name || !number) return NULL;
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].trunk_name, trunk_name) != 0) continue;
    if (strcmp(reg_list[i].number, number) == 0) {
      reg = &reg_list[i];
      break;
    }
  }
  return reg;
}

/* Fill ext_reg_t* array for extensions registered on trunk. *out (array of pointers) freed by caller. Returns count. */
static size_t get_ext_regs_for_trunk(const char *trunk_name, ext_reg_t ***out) {
  ext_reg_t **list = NULL;
  size_t n = 0;
  time_t now = time(NULL);
  if (!reg_list_ready || !reg_list || !trunk_name || !out) return 0;
  *out = NULL;
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].trunk_name, trunk_name) != 0) continue;
    ext_reg_t **new_list = (ext_reg_t **)realloc(list, (n + 1) * sizeof(ext_reg_t *));
    if (!new_list) break;
    list = new_list;
    list[n++] = &reg_list[i];
  }
  *out = list;
  return n;
}

/* Fill ext_reg_t* array for an extension number (any trunk). *out freed by caller. Returns count. */
static size_t get_ext_regs_for_extension(const char *ext_number, ext_reg_t ***out) {
  ext_reg_t **list = NULL;
  size_t n = 0;
  time_t now = time(NULL);
  if (!reg_list_ready || !reg_list || !ext_number || !out) return 0;
  *out = NULL;
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].number, ext_number) != 0) continue;
    ext_reg_t **new_list = (ext_reg_t **)realloc(list, (n + 1) * sizeof(ext_reg_t *));
    if (!new_list) break;
    list = new_list;
    list[n++] = &reg_list[i];
  }
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
  log_info("REGISTER digest: username=\"%s\"", digest_user);
  HASHHEX ha1, response_hex;
  digest_calc_ha1("MD5", digest_user, realm, password, nonce, cnonce, ha1);
  HASHHEX hent = "";
  /* Server uses legacy only (RFC 2069): response = MD5(HA1:nonce:HA2). Ignore qop/nc/cnonce for verification. */
  digest_calc_response(ha1, nonce, NULL, NULL, NULL, method, uri, hent, response_hex);
  int ok = (strcasecmp((char *)response_hex, client_response) == 0);
  if (!ok)
    log_info("REGISTER digest: mismatch calculated=\"%s\" client=\"%s\"", (char *)response_hex, client_response ? client_response : "(null)");
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

static int sdp_build_offer_to_callee(upbx_config *cfg, const char *caller_body, size_t caller_body_len,
  const char *call_id_number, const char *call_id_host, int cseq, int call_direction,
  uint16_t *caller_ports, size_t max_caller_ports, size_t *n_caller_ports,
  char **new_body_out, size_t *new_len_out);
static int sdp_build_answer_to_caller(upbx_config *cfg, const char *callee_body, size_t callee_body_len,
  const char *call_id_number, const char *call_id_host, int cseq,
  const uint16_t *caller_ports, size_t n_caller_ports,
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
  log_trace("REGISTER: step entry");
  /* Learn the address the client used to reach us (Request-URI host) for Via/SDP when advertise is not set */
  {
    char h[256], p[32];
    h[0] = p[0] = '\0';
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
      size_t hl = strlen(h);
      if (hl < sizeof(learned_advertise_host)) {
        memcpy(learned_advertise_host, h, hl + 1);
        if (p[0]) {
          size_t pl = strlen(p);
          if (pl < sizeof(learned_advertise_port)) memcpy(learned_advertise_port, p, pl + 1);
          else memcpy(learned_advertise_port, "5060", 5);
        } else
          memcpy(learned_advertise_port, "5060", 5);
      }
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
  char *raw_uri_user = user_buf[0] ? strdup(user_buf) : NULL;  /* original username (e.g. 206%40finwo) for digest + stored as reg.uri_user */
  decode_percent_at_inplace(user_buf);  /* support 100%40trunkname same as 100@trunkname */
  const char *user = user_buf;
  if (!user[0]) {
    free(raw_uri_user);
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
    free(raw_uri_user);
    char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  /* Look up extension by number only (no trunk marker); config uses [ext:number]. */
  config_extension *ext = get_extension_config(cfg, extension_num);
  if (!ext) {
    log_info("REGISTER: 403 Forbidden — extension \"%s\" not in config (username \"%s\")", extension_num, user);
    free(raw_uri_user);
    free(extension_num);
    char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  config_trunk *trunk = resolve_trunk_for_extension(cfg, extension_num, user);
  if (!trunk) {
    free(raw_uri_user);
    free(extension_num);
    char *r = build_reply(req_buf, req_len, 404, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  /* Get Authorization from parser (single place; no string scraping). */
  const char *auth_val;
  size_t auth_len;
  int has_auth = sip_header_get(req_buf, req_len, "Authorization", &auth_val, &auth_len);
  log_trace("REGISTER: extension_num=%s trunk=%s has_Authorization=%d", extension_num, trunk->name, has_auth ? 1 : 0);

  /* Plugin EXTENSION.REGISTER: can DENY, ALLOW (with optional custom data), or CONTINUE (built-in auth). */
  int plugin_allow = -1;
  char *plugin_custom = NULL;
  if (plugin_count() > 0)
    plugin_query_register(extension_num, trunk->name, user, &plugin_allow, &plugin_custom);
  if (plugin_allow == 0) {
    log_info("REGISTER: 403 Forbidden — plugin denied extension %s", extension_num);
    free(raw_uri_user);
    free(extension_num);
    free(plugin_custom);
    char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  if (plugin_allow != 1) {
    /* Built-in auth: require Authorization Digest. No header → 401 immediately (avoid parser/mutex path). */
    log_trace("REGISTER: step 401 path plugin-dont-deny");
    if (!has_auth || !ext->secret) {
      log_trace("REGISTER: step 401 path no-auth-or-no-secret");
      log_trace("REGISTER: sending 401 (no Authorization or no secret), returning");
      log_info("REGISTER: 401 Unauthorized — sending Digest challenge for extension %s (no credentials or no secret)", extension_num);
      char *r = build_reply(req_buf, req_len, 401, 0, 1, NULL);
      if (r) {
        log_hexdump_trace(r, strlen(r));
        send_response_buf(ctx, r, strlen(r));
        free(r);
      }
      free(raw_uri_user);
      free(extension_num);
      return;
    }
    char *auth_user = NULL, *auth_stripped = NULL;
    log_trace("REGISTER: step about to parse Authorization digest");
    if (!sip_parse_authorization_digest(req_buf, req_len, &auth_user, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
      log_trace("REGISTER: step parse failed, sending 401 invalid auth");
      log_trace("REGISTER: sending 401 (invalid Authorization), returning");
      log_info("REGISTER: 401 Unauthorized — sending Digest challenge for extension %s (no credentials or no secret)", extension_num);
      char *r = build_reply(req_buf, req_len, 401, 0, 1, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      free(raw_uri_user);
      free(extension_num);
      free(auth_user);
      return;
    }
    if (auth_user)
      auth_stripped = extension_part_from_username(auth_user);  /* before first @ or %40; digest uses raw auth_user */
    if (!auth_stripped || strcmp(auth_stripped, extension_num) != 0) {
      log_info("REGISTER: 403 Forbidden — Authorization username (stripped \"%s\") does not match extension \"%s\"", auth_stripped ? auth_stripped : "(null)", extension_num);
      free(raw_uri_user);
      free(auth_user); free(auth_stripped); free(extension_num);
      char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return;
    }
    /* Use Authorization header username for digest (match siproxd plugin_upbx: client sends e.g. "205@finwo"). */
    if (!verify_digest(req_buf, req_len, "REGISTER", ext->secret, AUTH_REALM, auth_user)) {
      log_info("REGISTER: 403 Forbidden — digest verification failed for extension %s", extension_num);
      free(raw_uri_user);
      free(extension_num);
      free(auth_user);
      free(auth_stripped);
      char *r = build_reply(req_buf, req_len, 403, 0, 0, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return;
    }
    free(auth_user);
    free(auth_stripped);
    /* keep raw_uri_user for storing in reg below */
  }

  /* Store raw_uri_user in reg (transfer ownership); free if we never stored (e.g. early return above already freed it) */
  log_trace("REGISTER: step auth OK, extension=%s", extension_num);
  log_trace("REGISTER: step set reg_list_ready");
  reg_list_ready = 1;
  log_trace("REGISTER: step get_contact_value");
  char *contact_val = get_contact_value(req_buf, req_len);
  log_trace("REGISTER: step contact_val done, loop reg_count=%zu", reg_count);
  for (size_t i = 0; i < reg_count; i++) {
    if (strcmp(reg_list[i].number, extension_num) == 0) {
      log_trace("REGISTER: step found existing reg at i=%zu", i);
      free(reg_list[i].trunk_name);
      free(reg_list[i].contact);
      free(reg_list[i].uri_user);
      free(reg_list[i].plugin_data);
      reg_list[i].trunk_name = strdup(trunk->name);
      reg_list[i].contact = contact_val ? contact_val : strdup("");
      reg_list[i].uri_user = raw_uri_user;  /* transfer ownership */
      raw_uri_user = NULL;
      reg_list[i].plugin_data = plugin_custom;
      reg_list[i].expires = time(NULL) + DEFAULT_EXPIRES;
      if (!contact_val) contact_val = strdup("");
      free(extension_num);
      log_trace("REGISTER: step update path before build_reply");
      { char *r = build_reply(req_buf, req_len, 200, 1, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
      log_trace("REGISTER: step update path after send");
      reg_list_notify_pending = 1;
      log_trace("REGISTER: step update path return");
      return;
    }
  }
  log_trace("REGISTER: step after loop no match");
  if (reg_count >= reg_cap) {
    size_t newcap = reg_cap ? reg_cap * 2 : 8;
    ext_reg_t *p = realloc(reg_list, newcap * sizeof(ext_reg_t));
    if (!p) { free(extension_num); free(plugin_custom); free(contact_val);
      char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return; }
    reg_list = p;
    reg_cap = newcap;
  }
  log_trace("REGISTER: step new path assign slot");
  reg_list[reg_count].number = extension_num;
  reg_list[reg_count].uri_user = raw_uri_user;  /* transfer ownership */
  raw_uri_user = NULL;
  reg_list[reg_count].trunk_name = strdup(trunk->name);
  reg_list[reg_count].contact = contact_val ? contact_val : strdup("");
  reg_list[reg_count].plugin_data = plugin_custom;
  reg_list[reg_count].expires = time(NULL) + DEFAULT_EXPIRES;
  reg_count++;
  log_trace("REGISTER: step new path before build_reply");
  { char *r = build_reply(req_buf, req_len, 200, 1, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
  log_trace("REGISTER: step new path after send");
  reg_list_notify_pending = 1;
  log_trace("REGISTER: step new path done");
  free(raw_uri_user);  /* no-op if transferred to reg */
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
    body_ptr, body_len, NULL);
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
  char via_buf[512], from_buf[384], to_buf[384], call_id_buf[256], cseq_buf[64], contact_buf[256];
  via_buf[0] = from_buf[0] = to_buf[0] = call_id_buf[0] = cseq_buf[0] = contact_buf[0] = '\0';
  sip_header_copy(req_buf, req_len, "Via", via_buf, sizeof(via_buf));
  sip_header_copy(req_buf, req_len, "From", from_buf, sizeof(from_buf));
  sip_header_copy(req_buf, req_len, "To", to_buf, sizeof(to_buf));
  sip_header_copy(req_buf, req_len, "Call-ID", call_id_buf, sizeof(call_id_buf));
  sip_header_copy(req_buf, req_len, "CSeq", cseq_buf, sizeof(cseq_buf));
  sip_header_copy(req_buf, req_len, "Contact", contact_buf, sizeof(contact_buf));
  const char *body_ptr = NULL;
  size_t body_len = 0;
  sip_request_get_body(req_buf, req_len, &body_ptr, &body_len);
  for (size_t i = 0; i < n_targets; i++) {
    if (!targets[i] || !targets[i][0]) continue;
    char host[256], port[32];
    if (contact_to_host_port(targets[i], host, sizeof(host), port, sizeof(port)) != 0) continue;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) continue;
    char req_uri[256];
    sip_format_request_uri("", host, port, req_uri, sizeof(req_uri));
    char *inv = sip_build_request_parts("INVITE", req_uri,
      via_buf[0] ? via_buf : NULL, from_buf[0] ? from_buf : NULL, to_buf[0] ? to_buf : NULL,
      call_id_buf[0] ? call_id_buf : NULL, cseq_buf[0] ? cseq_buf : NULL, contact_buf[0] ? contact_buf : NULL,
      body_ptr, body_len, NULL);
    if (inv) {
      udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, inv, strlen(inv));
      free(inv);
    }
    freeaddrinfo(res);
  }
  { char *r = build_reply(req_buf, req_len, 100, 0, 0, NULL); if (r) { send_response_buf(ctx, r, strlen(r)); free(r); } }
}

static int parse_listen_addr(const char *addr, char *host, size_t host_size, char *port, size_t port_size);
static int get_advertise_addr(upbx_config *cfg, char *host_out, size_t host_size, char *port_out, size_t port_size);

/* Apply overflow action for one call (busy/redirect/include). Single-threaded. */
static void overflow_apply_one(incoming_call_t *call, upbx_config *cfg, int sockfd) {
  if (!call || !call->trunk) return;
  if (call->answered || call->overflow_done) return;
  int timeout_sec = call->trunk->overflow_timeout;
  if (timeout_sec <= 0) return;
  time_t deadline = call->created_at + (time_t)timeout_sec;
  if (time(NULL) < deadline) return;
  call->overflow_done = 1;
  const char *strategy = call->trunk->overflow_strategy ? call->trunk->overflow_strategy : "none";
  int do_busy = 0, do_include = 0, do_redirect = 0;
  if (strcasecmp(strategy, "busy") == 0) do_busy = 1;
  else if (strcasecmp(strategy, "include") == 0 && call->trunk->overflow_target && call->trunk->overflow_target[0]) do_include = 1;
  else if (strcasecmp(strategy, "redirect") == 0 && call->trunk->overflow_target && call->trunk->overflow_target[0]) do_redirect = 1;
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
      if (c) call_remove_locked(c);
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
          char via_host[256], via_port[32];
          int have_via = (get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0);
          char via_buf[256], from_buf[384], to_buf[384], call_id_buf[128], cseq_buf[64];
          via_buf[0] = from_buf[0] = to_buf[0] = call_id_buf[0] = cseq_buf[0] = '\0';
          if (have_via) sip_make_via_line(via_host, via_port, via_buf, sizeof(via_buf));
          sip_header_copy(orig_invite, orig_len, "From", from_buf, sizeof(from_buf));
          sip_header_copy(orig_invite, orig_len, "To", to_buf, sizeof(to_buf));
          sip_header_copy(orig_invite, orig_len, "Call-ID", call_id_buf, sizeof(call_id_buf));
          sip_header_copy(orig_invite, orig_len, "CSeq", cseq_buf, sizeof(cseq_buf));
          char req_uri[256];
          sip_format_request_uri(overflow_reg->number ? overflow_reg->number : "", host, port, req_uri, sizeof(req_uri));
          const char *body_ptr = NULL;
          size_t body_len = 0;
          char *new_body = NULL;
          size_t new_body_len = 0;
          if (sip_request_get_body(orig_invite, orig_len, &body_ptr, &body_len) && body_len > 0) {
            int cseq = get_cseq_number(orig_invite, orig_len);
            sdp_build_offer_to_callee(cfg, body_ptr, body_len, call_id_buf, "", cseq, RTP_RELAY_CALL_INCOMING,
              call->rtp_caller_ports, (size_t)8, &call->n_rtp_caller_ports, &new_body, &new_body_len);
          }
          char *inv = sip_build_request_parts("INVITE", req_uri,
            via_buf[0] ? via_buf : NULL, from_buf[0] ? from_buf : NULL, to_buf[0] ? to_buf : NULL,
            call_id_buf[0] ? call_id_buf : NULL, cseq_buf[0] ? cseq_buf : NULL, NULL,
            new_body, new_body_len, NULL);
          free(new_body);
          if (inv) {
            udp_send_to(sockfd, res->ai_addr, res->ai_addrlen, inv, strlen(inv));
            free(inv);
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

/* Protothread: every ~500ms walk call_list and apply overflow for timed-out calls. */
static struct pt pt_overflow;
static time_t overflow_last_run;

static PT_THREAD(overflow_pt(struct pt *pt, upbx_config *cfg, int sockfd)) {
  PT_BEGIN(pt);
  overflow_last_run = 0;
  for (;;) {
    time_t now = time(NULL);
    if (now - overflow_last_run >= 1) {  /* run at most once per second */
      overflow_last_run = now;
      for (incoming_call_t *c = call_list; c; ) {
        incoming_call_t *next = c->next;
        overflow_apply_one(c, cfg, sockfd);
        c = next;
      }
    }
    PT_YIELD(pt);
  }
  PT_END(pt);
}

/* Fork INVITE to a list of extension registrations; create call, send 100. trunk may be NULL (ext-to-ext). Caller frees exts. */
static void fork_invite_to_extension_regs(upbx_config *cfg, const char *req_buf, size_t req_len, sip_send_ctx *ctx,
  ext_reg_t **exts, size_t n_ext, config_trunk *trunk, const char *source_str) {
  char via_host[256], via_port[32];
  if (get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) != 0) {
    log_info("INVITE fork: get_advertise_addr failed");
    char *r = build_reply(req_buf, req_len, 503, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  log_info("INVITE fork: forking to %zu extension(s)", n_ext);
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
  call->created_at = time(NULL);
  call->n_rtp_caller_ports = 0;
  /* Store caller Via value only (sip_build_response_parts expects value and emits "Via: %s"). */
  {
    char via_val_buf[512];
    via_val_buf[0] = '\0';
    sip_header_copy(req_buf, req_len, "Via", via_val_buf, sizeof(via_val_buf));
    call->caller_via = (via_val_buf[0] ? strdup(via_val_buf) : NULL);
  }

  /* Insert call into list before sending INVITEs so responses (100, 180, 200) can be matched and forwarded to caller (RFC 3261) */
  call->next = call_list;
  call_list = call;

  if (!(trunk && trunk->overflow_timeout > 0 && trunk->overflow_strategy && trunk->overflow_strategy[0] &&
      strcasecmp(trunk->overflow_strategy, "none") != 0)) {
    call->overflow_done = 1;
  }

  int cseq = get_cseq_number(req_buf, req_len);
  char cseq_buf[64];
  cseq_buf[0] = '\0';
  sip_header_copy(req_buf, req_len, "CSeq", cseq_buf, sizeof(cseq_buf));
  /* Start RTP proxy legs and rewrite SDP once; use same body for all forks so callee gets our RTP address */
  const char *body;
  size_t body_len;
  char *relay_body = NULL;
  size_t relay_body_len = 0;
  if (sip_request_get_body(req_buf, req_len, &body, &body_len) && body_len > 0 &&
      sdp_build_offer_to_callee(cfg, body, body_len, call_id_buf, "", cseq, RTP_RELAY_CALL_INCOMING,
          call->rtp_caller_ports, (size_t)8, &call->n_rtp_caller_ports, &relay_body, &relay_body_len) == 0 && relay_body) {
    /* relay_body will be used in loop; freed after loop */
  } else if (relay_body) {
    free(relay_body);
    relay_body = NULL;
  }

  char via_buf[256];
  sip_make_via_line(via_host, via_port, via_buf, sizeof(via_buf));

  for (size_t i = 0; i < n_ext; i++) {
    char host[256], port[32];
    if (contact_to_host_port(exts[i]->contact, host, sizeof(host), port, sizeof(port)) != 0) {
      log_info("INVITE fork: skip %s, contact_to_host_port failed (contact=%s)", exts[i]->number ? exts[i]->number : "(null)", exts[i]->contact ? exts[i]->contact : "(null)");
      continue;
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
      log_info("INVITE fork: skip %s, getaddrinfo(%s,%s) failed", exts[i]->number ? exts[i]->number : "(null)", host, port);
      continue;
    }
    const char *req_uri_user = (exts[i]->uri_user && exts[i]->uri_user[0]) ? exts[i]->uri_user : exts[i]->number;
    char req_uri[256];
    sip_format_request_uri(req_uri_user ? req_uri_user : "", host, port, req_uri, sizeof(req_uri));
    char from_val[384], to_val[384], contact_val[256];
    from_val[0] = to_val[0] = contact_val[0] = '\0';
    if (source_str) {
      config_extension *ext_caller = get_extension_config(cfg, source_str);
      config_extension *ext_callee = get_extension_config(cfg, exts[i]->number ? exts[i]->number : "");
      const char *caller_display = (ext_caller && ext_caller->name && ext_caller->name[0]) ? ext_caller->name : NULL;
      const char *callee_display = (ext_callee && ext_callee->name && ext_callee->name[0]) ? ext_callee->name : NULL;
      const char *callee_num = exts[i]->number ? exts[i]->number : "";
      sip_format_from_to_value(caller_display, source_str, via_host, via_port, from_val, sizeof(from_val));
      sip_format_from_to_value(callee_display, callee_num, via_host, via_port, to_val, sizeof(to_val));
      sip_format_contact_uri_value(source_str, via_host, via_port, contact_val, sizeof(contact_val));
    }
    char *inv = sip_build_request_parts("INVITE", req_uri,
      via_buf, from_val[0] ? from_val : NULL, to_val[0] ? to_val : NULL,
      call_id_buf[0] ? call_id_buf : NULL, cseq_buf[0] ? cseq_buf : NULL,
      contact_val[0] ? contact_val : NULL,
      relay_body, relay_body_len, NULL);
    if (inv) {
      size_t send_len = strlen(inv);
      log_info("INVITE fork: sending INVITE to %s at %s:%s Request-URI: %s", exts[i]->number ? exts[i]->number : "(null)", host, port, req_uri);
      log_hexdump_trace(inv, send_len);
      udp_send_to(ctx->sockfd, res->ai_addr, res->ai_addrlen, inv, send_len);
      fork_peer_t *new_forks = realloc(call->forks, (call->n_forks + 1) * sizeof(fork_peer_t));
      if (new_forks) {
        call->forks = new_forks;
        memcpy(&call->forks[call->n_forks].peer, res->ai_addr, res->ai_addrlen);
        call->forks[call->n_forks].peerlen = res->ai_addrlen;
        call->forks[call->n_forks].ext_number = exts[i]->number ? strdup(exts[i]->number) : NULL;
        call->n_forks++;
      }
      free(inv);
    }
    freeaddrinfo(res);
  }
  if (relay_body) free(relay_body);

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
  if (!reg_list_ready || !reg_list) {
    free(ext_num);
    char *r = build_reply(buf, len, 404, 0, 0, NULL);
    if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
    return;
  }
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= time(NULL)) continue;
    if (strcmp(reg_list[i].number, ext_num) == 0) {
      reg = &reg_list[i];
      break;
    }
  }
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
  log_info("INVITE To=%s From=%s Call-ID=%.32s", to_user[0] ? to_user : "(null)", from_user[0] ? from_user : "(null)", call_id);

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

  if (from_ext[0] && get_extension_config(cfg, from_ext)) {
    char *ext_num = strdup(from_ext);
    if (!ext_num) {
      char *r = build_reply(buf, len, 503, 0, 0, NULL);
      if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
      return;
    }
    if (to_ext[0] && get_extension_config(cfg, to_ext) && strcmp(ext_num, to_ext) != 0) {
      ext_reg_t **exts = NULL;
      size_t n_ext = get_ext_regs_for_extension(to_ext, &exts);
      if (n_ext > 0 && exts) {
        log_info("INVITE %s->%s: extension-to-extension, forking to %zu reg(s)", ext_num, to_ext, n_ext);
        fork_invite_to_extension_regs(cfg, buf, len, ctx, exts, n_ext, NULL, ext_num);
        free(exts);
        free(ext_num);
        return;
      }
      /* RFC 3261: callee not registered → 480 Temporarily Unavailable so caller gets clear failure */
      if (n_ext == 0) {
        log_info("INVITE %s->%s: no registration for callee %s, sending 480", ext_num, to_ext, to_ext);
        char *r = build_reply(buf, len, 480, 0, 0, NULL);
        if (r) { send_response_buf(ctx, r, strlen(r)); free(r); }
        free(exts);
        free(ext_num);
        return;
      }
      free(exts);
    }
    ext_reg_t *reg = NULL;
    if (reg_list_ready && reg_list) {
      for (size_t i = 0; i < reg_count; i++) {
        if (reg_list[i].expires <= time(NULL)) continue;
        if (strcmp(reg_list[i].number, ext_num) == 0) { reg = &reg_list[i]; break; }
      }
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
        override_buf = build_invite_with_uri(buf, len, target_override, req_host, req_port);
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

/* Forward a SIP response from a forked leg to the caller. Build a new response from parts (no callee packet forwarded). */
static void handle_sip_response(upbx_config *cfg, const char *buf, size_t len, sip_send_ctx *ctx) {
  const char *call_id_val;
  size_t call_id_len;
  if (!sip_header_get(buf, len, "Call-ID", &call_id_val, &call_id_len) || call_id_len == 0) return;
  char call_id_buf[256];
  if (call_id_len >= sizeof(call_id_buf)) return;
  memcpy(call_id_buf, call_id_val, call_id_len);
  call_id_buf[call_id_len] = '\0';
  int code = sip_response_status_code(buf, len);
  char peer_str[64];
  peer_to_str(&ctx->peer, ctx->peerlen, peer_str, sizeof(peer_str));
  log_info("SIP response from %s code=%d Call-ID %.32s", peer_str, code, call_id_buf);
  incoming_call_t *call = call_find_locked(call_id_buf);
  if (!call) {
    log_info("SIP response: no matching call for Call-ID %.32s, dropping", call_id_buf);
    return;
  }

  /* Reason phrase: from callee or default */
  char reason_buf[64];
  const char *reason = NULL;
  if (sip_response_reason_phrase(buf, len, reason_buf, sizeof(reason_buf)))
    reason = reason_buf;
  else
    reason = reason_phrase(code);

  /* CSeq from callee response (full value e.g. "1 INVITE") */
  char cseq_buf[64];
  cseq_buf[0] = '\0';
  const char *cseq_val = NULL;
  {
    const char *v;
    size_t vlen;
    if (sip_header_get(buf, len, "CSeq", &v, &vlen) && vlen > 0 && vlen < sizeof(cseq_buf)) {
      memcpy(cseq_buf, v, vlen);
      cseq_buf[vlen] = '\0';
      cseq_val = cseq_buf;
    }
  }

  /* Resolve callee and advertise addr for From/To/Contact */
  const char *callee_num = NULL;
  for (size_t f = 0; f < call->n_forks; f++) {
    if (sockaddr_match(&ctx->peer, ctx->peerlen, &call->forks[f].peer, call->forks[f].peerlen)) {
      callee_num = call->forks[f].ext_number;
      break;
    }
  }
  if (!callee_num && call->dest_str) callee_num = call->dest_str;

  char via_host[256], via_port[32];
  int have_addr = get_advertise_addr(cfg, via_host, sizeof(via_host), via_port, sizeof(via_port)) == 0;
  config_extension *ext_callee = callee_num ? get_extension_config(cfg, callee_num) : NULL;
  const char *callee_display = (ext_callee && ext_callee->name && ext_callee->name[0]) ? ext_callee->name : NULL;
  /* From and Contact: masqueraded for this leg */
  char from_val[384], contact_val[256];
  from_val[0] = '\0';
  contact_val[0] = '\0';
  if (call->source_str && callee_num && have_addr) {
    sip_format_from_to_value(callee_display, callee_num, via_host, via_port, from_val, sizeof(from_val));
    sip_format_contact_uri_value(callee_num, via_host, via_port, contact_val, sizeof(contact_val));
  }

  /* To: caller's original To (no tag) + callee's tag from response */
  char to_val[384];
  to_val[0] = '\0';
  if (call->original_invite && call->original_invite_len > 0 &&
      sip_header_value_before_first_param(call->original_invite, call->original_invite_len, "To", to_val, sizeof(to_val))) {
    char tag_buf[64];
    tag_buf[0] = '\0';
    if (sip_header_get_param(buf, len, "To", "tag", tag_buf, sizeof(tag_buf)) && tag_buf[0])
      sip_append_tag_param(to_val, sizeof(to_val), tag_buf);
  }
  if (to_val[0] == '\0' && callee_num && have_addr)
    sip_format_from_to_value(callee_display, callee_num, via_host, via_port, to_val, sizeof(to_val));

  /* Body: for 2xx with SDP, rewrite; else none */
  char *body_buf = NULL;
  size_t body_len = 0;
  if (code >= 200 && code < 300 && call->n_rtp_caller_ports > 0) {
    const char *resp_body;
    size_t resp_body_len;
    if (sip_request_get_body(buf, len, &resp_body, &resp_body_len) && resp_body_len > 0) {
      int cseq = get_cseq_number(buf, len);
      if (sdp_build_answer_to_caller(cfg, resp_body, resp_body_len,
            call->call_id ? call->call_id : "", "", cseq,
            call->rtp_caller_ports, call->n_rtp_caller_ports,
            &body_buf, &body_len) != 0 || !body_buf) {
        body_buf = NULL;
        body_len = 0;
      }
    }
  }

  /* Build response from parts (no callee packet; no UA leakage). */
  const char *via_line = (call->caller_via && call->caller_via[0]) ? call->caller_via : NULL;
  char *forward = sip_build_response_parts(code, reason,
    via_line, from_val[0] ? from_val : NULL, to_val[0] ? to_val : NULL,
    call->call_id, cseq_val, contact_val[0] ? contact_val : NULL, "upbx",
    body_buf, body_len, NULL, 0, NULL);
  free(body_buf);
  if (!forward) return;
  size_t forward_len = strlen(forward);

  if (code == 180 || code == 183) {
    char dest_str[64];
    peer_to_str((const struct sockaddr_storage *)&call->caller_peer, call->caller_peerlen, dest_str, sizeof(dest_str));
    log_trace("SIP response: sending %d to caller at %s (%zu bytes)", code, dest_str, forward_len);
    log_hexdump_trace(forward, forward_len);
  }
  udp_send_to(ctx->sockfd, (struct sockaddr *)&call->caller_peer, call->caller_peerlen, forward, forward_len);
  free(forward);

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

/* Get host and port to advertise in Via/SDP: cfg->advertise if set, else learned from REGISTER Request-URI, else listen. Return 0 on success. */
static int get_advertise_addr(upbx_config *cfg, char *host_out, size_t host_size, char *port_out, size_t port_size) {
  const char *listen = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  if (cfg->advertise && cfg->advertise[0]) {
    const char *colon = strchr(cfg->advertise, ':');
    if (colon && colon != cfg->advertise) {
      return parse_listen_addr(cfg->advertise, host_out, host_size, port_out, port_size);
    }
    size_t n = strlen(cfg->advertise);
    if (n >= host_size) return -1;
    memcpy(host_out, cfg->advertise, n + 1);
    if (port_size > 0) { strncpy(port_out, "5060", port_size - 1); port_out[port_size - 1] = '\0'; }
    return 0;
  }
  if (learned_advertise_host[0]) {
    size_t n = strlen(learned_advertise_host);
    if (n >= host_size) return -1;
    memcpy(host_out, learned_advertise_host, n + 1);
    n = strlen(learned_advertise_port);
    if (n > 0 && n < port_size) memcpy(port_out, learned_advertise_port, n + 1);
    else if (port_size > 0) { strncpy(port_out, "5060", port_size - 1); port_out[port_size - 1] = '\0'; }
    return 0;
  }
  return parse_listen_addr(listen, host_out, host_size, port_out, port_size);
}

static int resolve_interface_to_in_addr(const char *ifname, struct in_addr *out);

/* Resolve host (IP, hostname, or interface name) to in_addr; return 0 on success. */
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
  if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    out->s_addr = sin->sin_addr.s_addr;
    freeaddrinfo(res);
    return 0;
  }
  if (resolve_interface_to_in_addr(host, out) == 0)
    return 0;
  return -1;
}

/* Build our own SDP offer for the callee leg (separate session). Uses caller's codecs only; our address/ports.
 * Starts INCOMING/OUTGOING relay legs per m= (any media). Fills caller_ports for answer. */
static int sdp_build_offer_to_callee(upbx_config *cfg, const char *caller_body, size_t caller_body_len,
  const char *call_id_number, const char *call_id_host, int cseq, int call_direction,
  uint16_t *caller_ports, size_t max_caller_ports, size_t *n_caller_ports,
  char **new_body_out, size_t *new_len_out) {
  sdp_media_block_t blocks[SDP_MAX_MEDIA];
  size_t n_media = 0;
  if (sdp_parse_all_media(caller_body, caller_body_len, blocks, SDP_MAX_MEDIA, &n_media) != 0)
    return -1;
  char adv_host[256], adv_port[32];
  if (get_advertise_addr(cfg, adv_host, sizeof(adv_host), adv_port, sizeof(adv_port)) != 0) {
    sdp_media_blocks_free(blocks, n_media);
    return -1;
  }
  struct in_addr advertise_addr, bind_addr, zero_addr;
  if (resolve_to_in_addr(adv_host, &advertise_addr) != 0) { sdp_media_blocks_free(blocks, n_media); return -1; }
  if (advertise_addr.s_addr == 0 || strcmp(adv_host, "0.0.0.0") == 0) { sdp_media_blocks_free(blocks, n_media); return -1; }
  bind_addr.s_addr = INADDR_ANY;
  zero_addr.s_addr = 0;
  char advertise_str[64];
  inet_ntop(AF_INET, &advertise_addr, advertise_str, sizeof(advertise_str));

  if (n_caller_ports) *n_caller_ports = 0;
  int our_ports[SDP_MAX_MEDIA];
  for (size_t i = 0; i < n_media; i++) our_ports[i] = -1;
  for (size_t i = 0; i < n_media; i++) {
    sdp_media_block_t *b = &blocks[i];
    int incoming_port = 0, outgoing_port = 0;
    int do_relay = (b->m_port > 0 && b->m_port <= 65535 && b->c_addr && b->c_addr_len > 0 &&
                    b->m_rest_len >= 4 && strncasecmp(b->m_rest, "RTP/", 4) == 0);
    if (do_relay) {
      char c_buf[64];
      size_t cl = b->c_addr_len < sizeof(c_buf) - 1 ? b->c_addr_len : sizeof(c_buf) - 1;
      memcpy(c_buf, b->c_addr, cl); c_buf[cl] = '\0';
      struct in_addr remote_addr;
      if (resolve_to_in_addr(c_buf, &remote_addr) == 0 &&
          rtp_relay_start_fwd(cfg, call_id_number ? call_id_number : "", call_id_host ? call_id_host : "",
              RTP_RELAY_DIR_INCOMING, call_direction, (int)i, bind_addr, &incoming_port, remote_addr, b->m_port, cseq) == 0 &&
          rtp_relay_start_fwd(cfg, call_id_number ? call_id_number : "", call_id_host ? call_id_host : "",
              RTP_RELAY_DIR_OUTGOING, call_direction, (int)i, bind_addr, &outgoing_port, zero_addr, 0, cseq) == 0) {
        our_ports[i] = outgoing_port;
        if (caller_ports && n_caller_ports && *n_caller_ports < max_caller_ports && incoming_port > 0 && incoming_port <= 65535) {
          caller_ports[*n_caller_ports] = (uint16_t)incoming_port;
          (*n_caller_ports)++;
        }
      }
    }
  }
  int ret = sdp_build(advertise_str, blocks, n_media, our_ports, 1, new_body_out, new_len_out);
  sdp_media_blocks_free(blocks, n_media);
  return ret;
}

/* Build our own SDP answer for the caller leg (separate session). Uses callee's codecs only; our address/ports.
 * Updates OUTGOING relay with callee's address per media. Caller sees only our SDP. */
static int sdp_build_answer_to_caller(upbx_config *cfg, const char *callee_body, size_t callee_body_len,
  const char *call_id_number, const char *call_id_host, int cseq,
  const uint16_t *caller_ports, size_t n_caller_ports,
  char **new_body_out, size_t *new_len_out) {
  sdp_media_block_t blocks[SDP_MAX_MEDIA];
  size_t n_media = 0;
  if (sdp_parse_all_media(callee_body, callee_body_len, blocks, SDP_MAX_MEDIA, &n_media) != 0)
    return -1;
  char adv_host[256], adv_port[32];
  if (get_advertise_addr(cfg, adv_host, sizeof(adv_host), adv_port, sizeof(adv_port)) != 0) {
    sdp_media_blocks_free(blocks, n_media);
    return -1;
  }
  struct in_addr advertise_addr, bind_addr;
  if (resolve_to_in_addr(adv_host, &advertise_addr) != 0) { sdp_media_blocks_free(blocks, n_media); return -1; }
  if (advertise_addr.s_addr == 0 || strcmp(adv_host, "0.0.0.0") == 0) { sdp_media_blocks_free(blocks, n_media); return -1; }
  bind_addr.s_addr = INADDR_ANY;
  char advertise_str[64];
  inet_ntop(AF_INET, &advertise_addr, advertise_str, sizeof(advertise_str));

  for (size_t i = 0; i < n_media; i++) {
    sdp_media_block_t *b = &blocks[i];
    if (b->m_port > 0 && b->m_port <= 65535 && b->c_addr && b->c_addr_len > 0 &&
        b->m_rest_len >= 4 && strncasecmp(b->m_rest, "RTP/", 4) == 0) {
      char c_buf[64];
      size_t cl = b->c_addr_len < sizeof(c_buf) - 1 ? b->c_addr_len : sizeof(c_buf) - 1;
      memcpy(c_buf, b->c_addr, cl); c_buf[cl] = '\0';
      struct in_addr callee_addr;
      if (resolve_to_in_addr(c_buf, &callee_addr) == 0) {
        int dummy = 0;
        rtp_relay_start_fwd(cfg, call_id_number ? call_id_number : "", call_id_host ? call_id_host : "",
            RTP_RELAY_DIR_OUTGOING, RTP_RELAY_CALL_INCOMING, (int)i, bind_addr, &dummy, callee_addr, b->m_port, cseq);
      }
    }
  }

  int port_per_media[SDP_MAX_MEDIA];
  for (size_t i = 0; i < n_media; i++)
    port_per_media[i] = ((size_t)i < n_caller_ports && caller_ports) ? (int)caller_ports[i] : 0;
  int ret = sdp_build(advertise_str, blocks, n_media, port_per_media, 0, new_body_out, new_len_out);
  sdp_media_blocks_free(blocks, n_media);
  return ret;
}

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

  if (rtp_relay_init(cfg) != 0)
    log_error("rtp_relay_init failed");

  const char *listen_addr = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  log_info("SIP binding to %s", listen_addr);
  int sockfd = udp_bind(listen_addr);
  if (sockfd < 0) {
    log_error("daemon_root: UDP bind %s failed", listen_addr);
    return;
  }
  log_info("SIP listening on UDP %s", listen_addr);
  if (cfg->trunk_count > 0)
    log_info("trunk registration started (%zu trunk(s))", cfg->trunk_count);
  notify_extension_and_trunk_lists(cfg);

  trunk_reg_start(cfg);

  PT_INIT(&pt_overflow);
  struct pt pt_trunk_reg;
  PT_INIT(&pt_trunk_reg);

  char buf[SIP_READ_BUF_SIZE];
  struct sockaddr_storage peer;
  socklen_t peerlen;

  for (;;) {
    fd_set r;
    FD_ZERO(&r);
    FD_SET(sockfd, &r);
    int maxfd = sockfd;
    rtp_relay_fill_fds(&r, &maxfd);
    trunk_reg_fill_fds(&r, &maxfd);

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
          log_info("SIP packet from %s (%zd bytes)", peer_str, (size_t)nr);
          udp_msg_t *msg = malloc(sizeof(udp_msg_t) + (size_t)nr + 1);
          if (msg) {
            memcpy(&msg->peer, &peer, sizeof(msg->peer));
            msg->peerlen = peerlen;
            msg->len = (size_t)nr;
            memcpy(msg->buf, buf, (size_t)nr);
            msg->buf[nr] = '\0';
            handle_udp_msg(cfg, msg, sockfd);
          }
          if (reg_list_notify_pending) {
            reg_list_notify_pending = 0;
            notify_extension_and_trunk_lists(cfg);
          }
        }
      }
      rtp_relay_poll(&r);
      trunk_reg_poll(&r);
    }
    PT_SCHEDULE(overflow_pt(&pt_overflow, cfg, sockfd));
    PT_SCHEDULE(trunk_reg_pt(&pt_trunk_reg, cfg));
  }
}
