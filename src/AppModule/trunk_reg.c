/*
 * Trunk registration: SIP client sending periodic REGISTER to upstream trunks over UDP.
 * Single-threaded: UDP sockets are non-blocking; main loop select() then trunk_reg_poll().
 * Refresh interval from Contact expires (minus 15s) or default 1800s.
 * Uses internal SIP parsing (sip_parse.c) and shared digest auth (common/digest_auth.c).
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

#include "common/pt.h"
#include "common/socket_util.h"
#include "common/hexdump.h"
#include "common/digest_auth.h"
#include "rxi/log.h"
#include "config.h"
#include "AppModule/sip_parse.h"
#include "AppModule/trunk_reg.h"

#define TRUNK_REG_DEFAULT_REFRESH  1800
#define TRUNK_REG_REFRESH_LEAD     15
#define TRUNK_REG_MIN_REFRESH      60
#define SIP_READ_BUF_SIZE          (64 * 1024)

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

static upbx_config *trunk_reg_cfg;
static trunk_state_t *trunk_states;
static size_t trunk_states_n;

/* Build REGISTER request using sip_parse (all wire formatting there). Caller frees returned buffer. Returns length or 0 on error. */
static size_t build_register(upbx_config *cfg, config_trunk *trunk, trunk_state_t *state,
    int with_auth, char **out_request) {
  log_trace("%s", __func__);
  const char *host = trunk->host;
  const char *port = (trunk->port && trunk->port[0]) ? trunk->port : "5060";
  const char *user = (trunk->username && trunk->username[0]) ? trunk->username : "";

  char uri_str[512], via_buf[256], to_val[512], from_val[512], contact_val[256], auth_val[512];
  uri_str[0] = via_buf[0] = to_val[0] = from_val[0] = contact_val[0] = auth_val[0] = '\0';

  sip_format_request_uri(user, host, port, uri_str, sizeof(uri_str));
  sip_make_via_line(host, port, via_buf, sizeof(via_buf));
  sip_wrap_angle_uri(uri_str, to_val, sizeof(to_val));
  {
    size_t n = strlen(to_val);
    if (n < sizeof(from_val) - 16) {
      memcpy(from_val, to_val, n + 1);
      char tag_str[24];
      snprintf(tag_str, sizeof(tag_str), "%ld", (long)rand());
      sip_append_tag_param(from_val, sizeof(from_val), tag_str);
    }
  }

  char call_id[128];
  if (with_auth && state && state->call_id && state->call_id[0]) {
    strncpy(call_id, state->call_id, sizeof(call_id) - 1);
    call_id[sizeof(call_id) - 1] = '\0';
  } else {
    time_t now = time(NULL);
    snprintf(call_id, sizeof(call_id), "%ld%ld@%s", (long)now, (long)rand(), host);
    if (state) {
      free(state->call_id);
      state->call_id = strdup(call_id);
    }
  }

  const char *listen = (cfg->listen && cfg->listen[0]) ? cfg->listen : "0.0.0.0:5060";
  char listen_host[256], listen_port[32];
  if (sip_parse_host_port(listen, listen_host, sizeof(listen_host), listen_port, sizeof(listen_port)))
    sip_format_contact_uri_value((trunk->username && trunk->username[0]) ? trunk->username : "upbx", listen_host, listen_port, contact_val, sizeof(contact_val));

  if (with_auth && state && state->auth_nonce && state->auth_realm && trunk->password && trunk->password[0]) {
    const char *alg = (state->auth_algorithm && state->auth_algorithm[0]) ? state->auth_algorithm : "MD5";
    HASHHEX HA1, Response;
    digest_calc_ha1(alg, user, state->auth_realm, trunk->password, state->auth_nonce, NULL, HA1);
    { HASHHEX hentity = ""; digest_calc_response(HA1, state->auth_nonce, NULL, NULL, NULL, "REGISTER", uri_str, hentity, Response); }
    sip_build_authorization_digest_value(user, state->auth_realm, state->auth_nonce, uri_str, (const char *)Response, alg, state->auth_opaque, auth_val, sizeof(auth_val));
  }

  const char *ua = (trunk->user_agent && trunk->user_agent[0]) ? trunk->user_agent : "upbx/1.0";
  size_t req_len = 0;
  char *req = sip_build_register_request(uri_str, via_buf, to_val, from_val, call_id, "1 REGISTER",
    contact_val[0] ? contact_val : NULL, TRUNK_REG_DEFAULT_REFRESH + TRUNK_REG_REFRESH_LEAD, 70, ua,
    auth_val[0] ? auth_val : NULL, &req_len);
  if (!req) return 0;
  *out_request = req;
  return req_len;
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
