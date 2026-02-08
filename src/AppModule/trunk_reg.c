/*
 * Trunk registration: SIP client sending periodic REGISTER to upstream trunks over UDP.
 * Runs as a neco coroutine; refresh interval from Contact expires (minus 15s) or default 1800s.
 * Uses minimal SIP parsing (no libosip2) and built-in MD5 for Digest auth.
 * Digest auth follows RFC 3261 (section 22, HTTP auth) and RFC 2617 (Digest scheme):
 * - digest uri = Request-URI from request line (same as REGISTER sip:...).
 * - Match siproxd plugin_upbx.c: use RFC 2069 (no qop) for trunk registration, i.e. response =
 *   MD5(HA1:nonce:HA2), and do not send nc, cnonce, qop. Many trunks work with this.
 */
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "AppModule/md5.h"
#include "tidwall/neco.h"
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

/* Per-trunk runtime state (auth from 401, next refresh time) */
typedef struct {
  time_t next_refresh;
  char *auth_nonce;
  char *auth_realm;
  char *auth_algorithm;  /* From WWW-Authenticate; default MD5 */
  char *auth_opaque;     /* Echo in Authorization if present */
  char *auth_qop;        /* From WWW-Authenticate; if "auth" or "auth-int" use qop response, else RFC 2069 */
  char *call_id;  /* For matching 401 response when retrying */
} trunk_state_t;

/* UDP receive timeout for trunk REGISTER response (nanoseconds). */
#define TRUNK_UDP_RECV_TIMEOUT_NS  (10 * NECO_SECOND)

#define REGISTER_BUF_SIZE 4096

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

/* Register one trunk; returns refresh interval in seconds or -1 on failure. */
static int register_one_trunk(upbx_config *cfg, size_t trunk_idx, trunk_state_t *state) {
  log_trace("%s", __func__);
  config_trunk *trunk = &cfg->trunks[trunk_idx];
  const char *port = (trunk->port && trunk->port[0]) ? trunk->port : "5060";
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  char *buf = NULL;
  char *req_str = NULL;
  size_t req_len;
  int refresh = -1;
  int status_code = 0;
  int retried = 0;
  int gai_ret;
  int got_response = 0;
  size_t buflen = 0;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  gai_ret = getaddrinfo(trunk->host, port, &hints, &res);
  if (gai_ret != 0 || !res) {
    log_warn("trunk %s: resolve %s:%s failed", trunk->name, trunk->host, port);
    return -1;
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd >= 0)
      break;
  }
  if (fd < 0) {
    freeaddrinfo(res);
    return -1;
  }
  {
    bool old;
    if (neco_setnonblock(fd, true, &old) != 0) {
      close(fd);
      freeaddrinfo(res);
      return -1;
    }
  }

  buf = malloc(SIP_READ_BUF_SIZE);
  if (!buf) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }

  for (;;) {
    req_len = build_register(cfg, trunk, state, (retried && state->auth_nonce && state->auth_realm) ? 1 : 0, &req_str);
    if (req_len == 0 || !req_str) {
      refresh = -1;
      break;
    }
    log_trace("trunk_reg: sending %zu bytes to trunk %s (%s:%s)", req_len, trunk->name, trunk->host, port);
    log_hexdump_trace(req_str, req_len);
    if (sendto(fd, req_str, req_len, 0, ai->ai_addr, ai->ai_addrlen) != (ssize_t)req_len) {
      free(req_str);
      refresh = -1;
      break;
    }
    free(req_str);
    req_str = NULL;

    /* Wait for response; parse with minimal parser (no libosip2). */
    {
      int64_t deadline = neco_now() + TRUNK_UDP_RECV_TIMEOUT_NS;
      ssize_t n;
      got_response = 0;
      for (;;) {
        if (neco_wait_dl(fd, NECO_WAIT_READ, deadline) != 0)
          break;
        n = recvfrom(fd, buf, SIP_READ_BUF_SIZE - 1, 0, NULL, NULL);
        if (n <= 0)
          continue;
        buf[n] = '\0';
        buflen = (size_t)n;
        if (!looks_like_sip(buf, buflen))
          continue;
        log_trace("trunk_reg: after looks_like_sip ok");
        if (buflen >= 12 && memcmp(buf, "SIP/2.0 100 ", 12) == 0)
          continue;
        log_trace("trunk_reg: after skip 100 check");
        sip_fixup_for_parse(buf, &buflen, SIP_READ_BUF_SIZE);
        if (!sip_security_check_raw(buf, buflen))
          continue;
        log_trace("trunk_reg: after sip_security_check_raw ok");
        log_hexdump_trace(buf, buflen);
        status_code = sip_response_status_code(buf, buflen);
        if (status_code == 0)
          continue;
        if (status_code == 100)
          continue;
        got_response = 1;
        break;
      }
      if (!got_response) {
        refresh = -1;
        break;
      }
    }

    log_trace("trunk_reg: response status_code=%d", status_code);
    if (status_code == 401 && !retried && trunk->password && trunk->password[0]) {
      log_trace("trunk_reg: 401 received, parsing WWW-Authenticate");
      free(state->auth_nonce);
      free(state->auth_realm);
      free(state->auth_algorithm);
      free(state->auth_opaque);
      free(state->auth_qop);
      state->auth_nonce = NULL;
      state->auth_realm = NULL;
      state->auth_algorithm = NULL;
      state->auth_opaque = NULL;
      state->auth_qop = NULL;
      if (sip_parse_www_authenticate(buf, buflen, &state->auth_nonce, &state->auth_realm,
              &state->auth_algorithm, &state->auth_opaque, &state->auth_qop)) {
        log_info("trunk %s: 401 parsed, retrying REGISTER with Digest (realm=%s, algorithm=%s, qop=%s)",
            trunk->name, state->auth_realm ? state->auth_realm : "(none)",
            state->auth_algorithm && state->auth_algorithm[0] ? state->auth_algorithm : "MD5",
            state->auth_qop && state->auth_qop[0] ? state->auth_qop : "(none)");
        retried = 1;
        continue;
      }
      log_warn("trunk %s: 401 but could not parse WWW-Authenticate Digest", trunk->name);
    }
    if (status_code >= 200 && status_code < 300) {
      log_trace("trunk_reg: before get_contact_expires");
      refresh = sip_response_contact_expires(buf, buflen);
      if (refresh > TRUNK_REG_REFRESH_LEAD)
        refresh -= TRUNK_REG_REFRESH_LEAD;
      else
        refresh = TRUNK_REG_DEFAULT_REFRESH;
      if (refresh < TRUNK_REG_MIN_REFRESH)
        refresh = TRUNK_REG_MIN_REFRESH;
      log_info("trunk %s: registered (refresh in %ds)", trunk->name, refresh);
    } else {
      log_warn("trunk %s: REGISTER failed %d", trunk->name, status_code);
      refresh = TRUNK_REG_DEFAULT_REFRESH; /* Retry later */
    }
    break;
  }

  free(buf);
  close(fd);
  freeaddrinfo(res);
  return refresh;
}

void trunk_reg_loop(int argc, void *argv[]) {
  log_trace("%s", __func__);
  upbx_config *cfg = (upbx_config *)argv[0];
  trunk_state_t *states = NULL;
  time_t now;
  time_t next_run;
  int64_t sleep_ns;
  size_t i;

  if (argc < 1 || !cfg || cfg->trunk_count == 0) {
    return;
  }

  states = calloc(cfg->trunk_count, sizeof(trunk_state_t));
  if (!states) {
    log_error("trunk_reg_loop: out of memory");
    return;
  }

  for (;;) {
    now = time(NULL);
    next_run = 0;

    for (i = 0; i < cfg->trunk_count; i++) {
      config_trunk *t = &cfg->trunks[i];
      if (!t->host || !t->host[0])
        continue;
      if (states[i].next_refresh == 0 || now >= states[i].next_refresh) {
        int ref = register_one_trunk(cfg, i, &states[i]);
        if (ref > 0)
          states[i].next_refresh = now + ref;
        else
          states[i].next_refresh = now + TRUNK_REG_DEFAULT_REFRESH;
      }
      if (states[i].next_refresh > 0 && (next_run == 0 || states[i].next_refresh < next_run))
        next_run = states[i].next_refresh;
    }

    if (next_run == 0)
      next_run = now + 60;
    if (next_run <= now)
      next_run = now + 60;
    sleep_ns = (int64_t)(next_run - now) * 1000000000;
    if (sleep_ns > 0)
      neco_sleep(sleep_ns);
  }
}
