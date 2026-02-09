/*
 * Trunk registration: SIP client sending periodic REGISTER to upstream trunks over UDP.
 * Single-threaded: UDP sockets are non-blocking; main loop select() then trunk_reg_poll().
 * Refresh interval from Contact expires (minus 15s) or default 1800s.
 * Uses minimal SIP parsing (no libosip2) and built-in MD5 for Digest auth.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "pt.h"
#include "AppModule/md5.h"
#include "socket_util.h"
#include "rxi/log.h"
#include "config.h"
#include "AppModule/sip_hexdump.h"
#include "AppModule/sip_parse.h"
#include "AppModule/trunk_reg.h"

#define TRUNK_REG_DEFAULT_REFRESH  1800
#define TRUNK_REG_REFRESH_LEAD     15
#define TRUNK_REG_MIN_REFRESH      60
#define SIP_READ_BUF_SIZE          (64 * 1024)
#define SIP_MAX_HEADERS            (32 * 1024)

/* Return true if buf[0..len-1] looks like a SIP message (has status/request line and \r\n\r\n). */
static bool looks_like_sip(const char *buf, size_t len) {
  log_trace("%s", __func__);
  if (len < 12)
    return false;
  size_t max = len < SIP_MAX_HEADERS ? len : SIP_MAX_HEADERS;
  for (size_t i = 0; i + 3 < max; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
      return true;
  }
  return false;
}

/* Digest auth (same as sip_server) */
#define HASHLEN 16
#define HASHHEXLEN 32
typedef unsigned char HASH[HASHLEN];
typedef unsigned char HASHHEX[HASHHEXLEN + 1];

static void cvt_hex(const unsigned char *bin, HASHHEX hex) {
  log_trace("%s", __func__);
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
  log_trace("%s", __func__);
  MD5_CTX ctx;
  HASH ha1;
  MD5_Init(&ctx);
  if (user) MD5_Update(&ctx, (unsigned char *)user, strlen(user));
  MD5_Update(&ctx, (unsigned char *)":", 1);
  if (realm) MD5_Update(&ctx, (unsigned char *)realm, strlen(realm));
  MD5_Update(&ctx, (unsigned char *)":", 1);
  if (password) MD5_Update(&ctx, (unsigned char *)password, strlen(password));
  MD5_Final(ha1, &ctx);
  if (alg && strcasecmp(alg, "md5-sess") == 0) {
    MD5_Init(&ctx);
    MD5_Update(&ctx, ha1, HASHLEN);
    MD5_Update(&ctx, (unsigned char *)":", 1);
    if (nonce) MD5_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
    MD5_Update(&ctx, (unsigned char *)":", 1);
    if (cnonce) MD5_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
    MD5_Final(ha1, &ctx);
  }
  cvt_hex(ha1, out);
}

static void digest_calc_response(HASHHEX ha1, const char *nonce, const char *nc,
    const char *cnonce, const char *qop, const char *method, const char *uri,
    HASHHEX hentity, HASHHEX out) {
  log_trace("%s", __func__);
  MD5_CTX ctx;
  HASH ha2, resphash;
  HASHHEX ha2hex;
  MD5_Init(&ctx);
  if (method) MD5_Update(&ctx, (unsigned char *)method, strlen(method));
  MD5_Update(&ctx, (unsigned char *)":", 1);
  if (uri) MD5_Update(&ctx, (unsigned char *)uri, strlen(uri));
  /* RFC 2617: for qop=auth-int only, HA2 = MD5(method:uri:MD5(entity)); for qop=auth, HA2 = MD5(method:uri) */
  if (qop && strcasecmp(qop, "auth-int") == 0 && hentity) {
    MD5_Update(&ctx, (unsigned char *)":", 1);
    MD5_Update(&ctx, (unsigned char *)hentity, HASHHEXLEN);
  }
  MD5_Final(ha2, &ctx);
  cvt_hex(ha2, ha2hex);
  MD5_Init(&ctx);
  MD5_Update(&ctx, ha1, HASHHEXLEN);
  MD5_Update(&ctx, (unsigned char *)":", 1);
  if (nonce) MD5_Update(&ctx, (unsigned char *)nonce, strlen(nonce));
  if (qop && *qop) {
    /* RFC 2617 with qop: request-digest = KD(H(A1), nonce ":" nc ":" cnonce ":" qop ":" H(A2)) */
    MD5_Update(&ctx, (unsigned char *)":", 1);
    if (nc) MD5_Update(&ctx, (unsigned char *)nc, strlen(nc));
    MD5_Update(&ctx, (unsigned char *)":", 1);
    if (cnonce) MD5_Update(&ctx, (unsigned char *)cnonce, strlen(cnonce));
    MD5_Update(&ctx, (unsigned char *)":", 1);
    MD5_Update(&ctx, (unsigned char *)qop, strlen(qop));
    MD5_Update(&ctx, (unsigned char *)":", 1);
  } else {
    /* RFC 2069: request-digest = KD(H(A1), nonce ":" H(A2)) — need ":" before H(A2) (match siproxd auth.c) */
    MD5_Update(&ctx, (unsigned char *)":", 1);
  }
  MD5_Update(&ctx, ha2hex, HASHHEXLEN);
  MD5_Final(resphash, &ctx);
  cvt_hex(resphash, out);
}

/* Per-trunk runtime state (auth from 401, next refresh time; in-flight reg socket) */
typedef struct {
  time_t next_refresh;
  char *auth_nonce;
  char *auth_realm;
  char *auth_algorithm;
  char *auth_opaque;
  char *auth_qop;
  char *call_id;
  int reg_fd;              /* -1 when idle; socket when waiting for REGISTER response */
  time_t reg_deadline;     /* when to give up waiting */
  struct addrinfo *reg_res; /* so we can retry sendto and free later */
} trunk_state_t;

#define TRUNK_UDP_RECV_TIMEOUT_SEC  10

#define REGISTER_BUF_SIZE 4096

static upbx_config *trunk_reg_cfg;
static trunk_state_t *trunk_states;
static size_t trunk_states_n;

/* Build REGISTER request as raw SIP string. Caller frees returned buffer. Returns length or 0 on error. */
static size_t build_register(upbx_config *cfg, config_trunk *trunk, trunk_state_t *state,
    int with_auth, char **out_request) {
  log_trace("%s", __func__);
  char *req = malloc(REGISTER_BUF_SIZE);
  if (!req) return 0;
  char *p = req;
  char *end = req + REGISTER_BUF_SIZE - 2;
  const char *host = trunk->host;
  const char *port = (trunk->port && trunk->port[0]) ? trunk->port : "5060";
  time_t now = time(NULL);
  char uri_str[512];
  char contact_str[256];
  const char *user = (trunk->username && trunk->username[0]) ? trunk->username : "";

  if (trunk->username && trunk->username[0])
    snprintf(uri_str, sizeof(uri_str), "sip:%s@%s", trunk->username, host);
  else
    snprintf(uri_str, sizeof(uri_str), "sip:%s", host);
  if (strcmp(port, "5060") != 0) {
    size_t ulen = strlen(uri_str);
    snprintf(uri_str + ulen, sizeof(uri_str) - ulen, ":%s", port);
  }

  p += snprintf(p, (size_t)(end - p), "REGISTER %s SIP/2.0\r\n", uri_str);
  p += snprintf(p, (size_t)(end - p), "Via: SIP/2.0/UDP %s:%s;branch=z9hG4bK%ld%ld\r\n", host, port, (long)now, (long)rand());
  p += snprintf(p, (size_t)(end - p), "To: <%s>\r\n", uri_str);
  p += snprintf(p, (size_t)(end - p), "From: <%s>;tag=%ld\r\n", uri_str, (long)rand());
  {
    char cid[128];
    if (with_auth && state && state->call_id && state->call_id[0]) {
      snprintf(cid, sizeof(cid), "%s", state->call_id);
    } else {
      snprintf(cid, sizeof(cid), "%ld%ld@%s", (long)now, (long)rand(), host);
      if (state) {
        free(state->call_id);
        state->call_id = strdup(cid);
      }
    }
    p += snprintf(p, (size_t)(end - p), "Call-ID: %s\r\n", cid);
  }
  p += snprintf(p, (size_t)(end - p), "CSeq: 1 REGISTER\r\n");
  {
    const char *listen = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
    const char *contact_user = (trunk->username && trunk->username[0]) ? trunk->username : "upbx";
    snprintf(contact_str, sizeof(contact_str), "<sip:%s@%s>", contact_user, listen);
    p += snprintf(p, (size_t)(end - p), "Contact: %s\r\n", contact_str);
  }
  p += snprintf(p, (size_t)(end - p), "Expires: %d\r\n", TRUNK_REG_DEFAULT_REFRESH + TRUNK_REG_REFRESH_LEAD);
  p += snprintf(p, (size_t)(end - p), "Max-Forwards: 70\r\n");
  p += snprintf(p, (size_t)(end - p), "User-Agent: %s\r\n",
      (trunk->user_agent && trunk->user_agent[0]) ? trunk->user_agent : "upbx/1.0");

  if (with_auth && state && state->auth_nonce && state->auth_realm && trunk->password && trunk->password[0]) {
    const char *alg = (state->auth_algorithm && state->auth_algorithm[0]) ? state->auth_algorithm : "MD5";
    /* Use RFC 2069 (no qop) for trunk, matching siproxd plugin_upbx.c: DigestCalcResponse(..., NULL, ...) */
    HASHHEX HA1, Response;
    digest_calc_ha1(alg, user, state->auth_realm, trunk->password,
        state->auth_nonce, NULL, HA1);
    { HASHHEX hentity = ""; digest_calc_response(HA1, state->auth_nonce, NULL, NULL, NULL, "REGISTER", uri_str, hentity, Response); }
    /* uri in digest = Request-URI from request line (same as siproxd osip_uri_to_str(req_uri)) */
    p += snprintf(p, (size_t)(end - p),
        "Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\"",
        user, state->auth_realm, state->auth_nonce, uri_str, (char *)Response);
    if (alg && alg[0]) p += snprintf(p, (size_t)(end - p), ",algorithm=%s", alg);
    if (state->auth_opaque && state->auth_opaque[0])
      p += snprintf(p, (size_t)(end - p), ",opaque=\"%s\"", state->auth_opaque);
    p += snprintf(p, (size_t)(end - p), "\r\n");
  }

  if (p >= end) { free(req); return 0; }
  p += snprintf(p, (size_t)(end - p), "\r\n");
  *out_request = req;
  return (size_t)(p - req);
}

/* Start registration for one trunk: create socket, send REGISTER, set state to waiting. Returns 0 on success. */
static int start_registration(upbx_config *cfg, size_t trunk_idx) {
  trunk_state_t *state = &trunk_states[trunk_idx];
  config_trunk *trunk = &cfg->trunks[trunk_idx];
  const char *port = (trunk->port && trunk->port[0]) ? trunk->port : "5060";
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  char *req_str = NULL;
  size_t req_len;
  int with_auth = (state->auth_nonce && state->auth_realm) ? 1 : 0;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(trunk->host, port, &hints, &res) != 0 || !res) {
    log_warn("trunk %s: resolve %s:%s failed", trunk->name, trunk->host, port);
    return -1;
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd >= 0) break;
  }
  if (fd < 0) {
    freeaddrinfo(res);
    return -1;
  }
  if (set_socket_nonblocking(fd, 1) != 0) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  req_len = build_register(cfg, trunk, state, with_auth, &req_str);
  if (req_len == 0 || !req_str) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  log_trace("trunk_reg: sending %zu bytes to trunk %s (%s:%s)", req_len, trunk->name, trunk->host, port);
  log_hexdump_trace(req_str, req_len);
  if (sendto(fd, req_str, req_len, 0, ai->ai_addr, ai->ai_addrlen) != (ssize_t)req_len) {
    free(req_str);
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  free(req_str);
  state->reg_fd = fd;
  state->reg_deadline = time(NULL) + TRUNK_UDP_RECV_TIMEOUT_SEC;
  state->reg_res = res;
  return 0;
}

/* Handle received response for trunk_idx. Close fd and clear state when done (success or failure). */
static void handle_reg_response(upbx_config *cfg, size_t trunk_idx, char *buf, size_t buflen) {
  trunk_state_t *state = &trunk_states[trunk_idx];
  config_trunk *trunk = &cfg->trunks[trunk_idx];
  int status_code = sip_response_status_code(buf, buflen);

  if (status_code == 401 && trunk->password && trunk->password[0]) {
    free(state->auth_nonce);
    free(state->auth_realm);
    free(state->auth_algorithm);
    free(state->auth_opaque);
    free(state->auth_qop);
    state->auth_nonce = state->auth_realm = state->auth_algorithm = state->auth_opaque = state->auth_qop = NULL;
    if (sip_parse_www_authenticate(buf, buflen, &state->auth_nonce, &state->auth_realm,
            &state->auth_algorithm, &state->auth_opaque, &state->auth_qop)) {
      log_info("trunk %s: 401 parsed, retrying REGISTER with Digest", trunk->name);
      char *req_str = NULL;
      size_t req_len = build_register(cfg, trunk, state, 1, &req_str);
      if (req_len > 0 && req_str && state->reg_res) {
        if (sendto(state->reg_fd, req_str, req_len, 0, state->reg_res->ai_addr, state->reg_res->ai_addrlen) == (ssize_t)req_len)
          state->reg_deadline = time(NULL) + TRUNK_UDP_RECV_TIMEOUT_SEC;
      }
      free(req_str);
      return;
    }
  }
  if (status_code >= 200 && status_code < 300) {
    int refresh = sip_response_contact_expires(buf, buflen);
    if (refresh > TRUNK_REG_REFRESH_LEAD) refresh -= TRUNK_REG_REFRESH_LEAD;
    else refresh = TRUNK_REG_DEFAULT_REFRESH;
    if (refresh < TRUNK_REG_MIN_REFRESH) refresh = TRUNK_REG_MIN_REFRESH;
    state->next_refresh = time(NULL) + refresh;
    log_info("trunk %s: registered (refresh in %ds)", trunk->name, refresh);
  } else if (status_code > 0) {
    log_warn("trunk %s: REGISTER failed %d", trunk->name, status_code);
    state->next_refresh = time(NULL) + TRUNK_REG_DEFAULT_REFRESH;
  }
  if (state->reg_fd >= 0) {
    close(state->reg_fd);
    state->reg_fd = -1;
  }
  if (state->reg_res) {
    freeaddrinfo(state->reg_res);
    state->reg_res = NULL;
  }
}

void trunk_reg_start(upbx_config *cfg) {
  if (!cfg || cfg->trunk_count == 0) return;
  trunk_reg_cfg = cfg;
  trunk_states_n = cfg->trunk_count;
  trunk_states = calloc(trunk_states_n, sizeof(trunk_state_t));
  if (!trunk_states) {
    log_error("trunk_reg_start: out of memory");
    trunk_states_n = 0;
    return;
  }
  for (size_t i = 0; i < trunk_states_n; i++)
    trunk_states[i].reg_fd = -1;
}

void trunk_reg_fill_fds(fd_set *read_set, int *maxfd) {
  for (size_t i = 0; i < trunk_states_n; i++) {
    if (trunk_states[i].reg_fd >= 0) {
      FD_SET(trunk_states[i].reg_fd, read_set);
      if (trunk_states[i].reg_fd > *maxfd) *maxfd = trunk_states[i].reg_fd;
    }
  }
}

void trunk_reg_poll(fd_set *read_set) {
  time_t now = time(NULL);
  char *buf = malloc(SIP_READ_BUF_SIZE);
  if (!buf) return;
  for (size_t i = 0; i < trunk_states_n; i++) {
    trunk_state_t *state = &trunk_states[i];
    if (state->reg_fd < 0) continue;
    if (now > state->reg_deadline) {
      if (state->reg_fd >= 0) { close(state->reg_fd); state->reg_fd = -1; }
      if (state->reg_res) { freeaddrinfo(state->reg_res); state->reg_res = NULL; }
      state->next_refresh = now + TRUNK_REG_DEFAULT_REFRESH;
      continue;
    }
    if (!FD_ISSET(state->reg_fd, read_set)) continue;
    ssize_t n = recvfrom(state->reg_fd, buf, SIP_READ_BUF_SIZE - 1, 0, NULL, NULL);
    if (n <= 0) continue;
    buf[n] = '\0';
    size_t buflen = (size_t)n;
    if (!looks_like_sip(buf, buflen)) continue;
    if (buflen >= 12 && memcmp(buf, "SIP/2.0 100 ", 12) == 0) continue;
    sip_fixup_for_parse(buf, &buflen, SIP_READ_BUF_SIZE);
    if (!sip_security_check_raw(buf, buflen)) continue;
    log_hexdump_trace(buf, buflen);
    if (sip_response_status_code(buf, buflen) == 100) continue;
    handle_reg_response(trunk_reg_cfg, i, buf, buflen);
  }
  free(buf);
}

PT_THREAD(trunk_reg_pt(struct pt *pt, upbx_config *cfg)) {
  PT_BEGIN(pt);
  for (;;) {
    time_t now = time(NULL);
    for (size_t i = 0; i < trunk_states_n; i++) {
      config_trunk *t = &cfg->trunks[i];
      if (!t->host || t->host[0] == '\0') continue;
      if (trunk_states[i].reg_fd >= 0) continue; /* already in flight */
      if (trunk_states[i].next_refresh != 0 && now < trunk_states[i].next_refresh) continue;
      start_registration(cfg, i);
    }
    PT_YIELD(pt);
  }
  PT_END(pt);
}
