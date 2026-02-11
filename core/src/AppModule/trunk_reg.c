/*
 * Trunk registration: SIP client sending periodic REGISTER to upstream trunks over UDP.
 * Name-keyed state; reads trunk config via live config API. Regex cache for rewrite rules.
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
#include "PluginModule/plugin.h"
#include "AppModule/sip_parse.h"
#include "AppModule/trunk_reg.h"

#define TRUNK_REG_DEFAULT_REFRESH  1800
#define TRUNK_REG_REFRESH_LEAD     15
#define TRUNK_REG_MIN_REFRESH      60
#define SIP_READ_BUF_SIZE          (64 * 1024)
#define TRUNK_PREFIX               "trunk:"
#define TRUNK_PREFIX_LEN           6
#ifndef UPBX_VERSION_STR
#define UPBX_VERSION_STR "0.1.0"
#endif

/* Per-trunk runtime state */
typedef struct {
  time_t next_refresh;
  char *auth_nonce;
  char *auth_realm;
  char *auth_algorithm;
  char *auth_opaque;
  char *auth_qop;
  char *call_id;
  int reg_fd;
  time_t reg_deadline;
  struct addrinfo *reg_res;
  int registered;
} trunk_state_t;

/* Name-keyed entry */
typedef struct {
  char *name;
  trunk_state_t state;
} trunk_entry_t;

#define TRUNK_UDP_RECV_TIMEOUT_SEC  10

static trunk_entry_t *trunk_entries;
static size_t trunk_entries_n;
static size_t trunk_entries_cap;

static void trunk_state_free(trunk_state_t *s) {
  free(s->auth_nonce);
  free(s->auth_realm);
  free(s->auth_algorithm);
  free(s->auth_opaque);
  free(s->auth_qop);
  free(s->call_id);
  s->auth_nonce = s->auth_realm = s->auth_algorithm = s->auth_opaque = s->auth_qop = s->call_id = NULL;
  if (s->reg_fd >= 0) { close(s->reg_fd); s->reg_fd = -1; }
  if (s->reg_res) { freeaddrinfo(s->reg_res); s->reg_res = NULL; }
}

static trunk_entry_t *trunk_find(const char *name) {
  for (size_t i = 0; i < trunk_entries_n; i++)
    if (trunk_entries[i].name && strcmp(trunk_entries[i].name, name) == 0)
      return &trunk_entries[i];
  return NULL;
}

static trunk_entry_t *trunk_find_or_add(const char *name) {
  trunk_entry_t *e = trunk_find(name);
  if (e) return e;
  if (trunk_entries_n >= trunk_entries_cap) {
    size_t new_cap = trunk_entries_cap ? trunk_entries_cap * 2 : 8;
    trunk_entry_t *p = realloc(trunk_entries, new_cap * sizeof(trunk_entry_t));
    if (!p) return NULL;
    trunk_entries = p;
    trunk_entries_cap = new_cap;
  }
  e = &trunk_entries[trunk_entries_n];
  e->name = strdup(name);
  if (!e->name) return NULL;
  memset(&e->state, 0, sizeof(e->state));
  e->state.reg_fd = -1;
  trunk_entries_n++;
  return e;
}

static void trunk_remove_at(size_t i) {
  trunk_state_free(&trunk_entries[i].state);
  free(trunk_entries[i].name);
  trunk_entries[i].name = NULL;
  if (i < trunk_entries_n - 1) {
    trunk_entries[i] = trunk_entries[trunk_entries_n - 1];
  }
  trunk_entries_n--;
}

static size_t build_register(const char *host, const char *port, const char *user, const char *password,
    const char *listen, const char *user_agent, trunk_state_t *state, int with_auth, char **out_request) {
  if (!host || !host[0]) return 0;
  const char *p = (port && port[0]) ? port : "5060";
  const char *u = (user && user[0]) ? user : "";

  char uri_str[512], via_buf[256], to_val[512], from_val[512], contact_val[256], auth_val[512];
  uri_str[0] = via_buf[0] = to_val[0] = from_val[0] = contact_val[0] = auth_val[0] = '\0';

  sip_format_request_uri(u, host, p, uri_str, sizeof(uri_str));
  sip_make_via_line(host, p, via_buf, sizeof(via_buf));
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

  const char *listen_addr = (listen && listen[0]) ? listen : "0.0.0.0:5060";
  char listen_host[256], listen_port[32];
  if (sip_parse_host_port(listen_addr, listen_host, sizeof(listen_host), listen_port, sizeof(listen_port)))
    sip_format_contact_uri_value((u[0]) ? u : "upbx", listen_host, listen_port, contact_val, sizeof(contact_val));

  if (with_auth && state && state->auth_nonce && state->auth_realm && password && password[0]) {
    const char *alg = (state->auth_algorithm && state->auth_algorithm[0]) ? state->auth_algorithm : "MD5";
    HASHHEX HA1, Response;
    digest_calc_ha1(alg, u, state->auth_realm, password, state->auth_nonce, NULL, HA1);
    { HASHHEX hentity = ""; digest_calc_response(HA1, state->auth_nonce, NULL, NULL, NULL, "REGISTER", uri_str, hentity, Response); }
    sip_build_authorization_digest_value(u, state->auth_realm, state->auth_nonce, uri_str, (const char *)Response, alg, state->auth_opaque, auth_val, sizeof(auth_val));
  }

  const char *ua = (user_agent && user_agent[0]) ? user_agent : "upbx/" UPBX_VERSION_STR;
  size_t req_len = 0;
  char *req = sip_build_register_request(uri_str, via_buf, to_val, from_val, call_id, "1 REGISTER",
    contact_val[0] ? contact_val : NULL, TRUNK_REG_DEFAULT_REFRESH + TRUNK_REG_REFRESH_LEAD, 70, ua,
    auth_val[0] ? auth_val : NULL, &req_len);
  if (!req) return 0;
  *out_request = req;
  return req_len;
}

static int start_registration(const char *trunk_name, const char *host, const char *port,
    const char *user, const char *password, const char *user_agent, trunk_state_t *state) {
  const char *p = (port && port[0]) ? port : "5060";
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  char *req_str = NULL;
  size_t req_len;
  int with_auth = (state->auth_nonce && state->auth_realm) ? 1 : 0;

  plugmod_resp_object *listen_obj = config_key_get("upbx", "listen");
  const char *listen = (listen_obj && (listen_obj->type == PLUGMOD_RESPT_BULK || listen_obj->type == PLUGMOD_RESPT_SIMPLE) && listen_obj->u.s) ? listen_obj->u.s : "0.0.0.0:5060";
  if (listen_obj) plugmod_resp_free(listen_obj);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(host, p, &hints, &res) != 0 || !res) {
    log_warn("trunk %s: resolve %s:%s failed", trunk_name, host, p);
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
  req_len = build_register(host, p, user, password, listen, user_agent, state, with_auth, &req_str);
  if (req_len == 0 || !req_str) {
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  log_trace("trunk_reg: sending %zu bytes to trunk %s (%s:%s)", req_len, trunk_name, host, p);
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

static void handle_reg_response(const char *trunk_name, trunk_state_t *state, char *buf, size_t buflen) {
  int status_code = sip_response_status_code(buf, buflen);
  log_trace("handle_reg_response: trunk=%s status=%d", trunk_name, status_code);

  if (status_code == 401) {
    char section[128];
    snprintf(section, sizeof(section), "trunk:%s", trunk_name);
    plugmod_resp_object *pw_obj = config_key_get(section, "password");
    const char *password = (pw_obj && (pw_obj->type == PLUGMOD_RESPT_BULK || pw_obj->type == PLUGMOD_RESPT_SIMPLE)) ? pw_obj->u.s : NULL;
    if (password && password[0]) {
      free(state->auth_nonce);
      free(state->auth_realm);
      free(state->auth_algorithm);
      free(state->auth_opaque);
      free(state->auth_qop);
      state->auth_nonce = state->auth_realm = state->auth_algorithm = state->auth_opaque = state->auth_qop = NULL;
      if (sip_parse_www_authenticate(buf, buflen, &state->auth_nonce, &state->auth_realm,
              &state->auth_algorithm, &state->auth_opaque, &state->auth_qop)) {
        log_debug("trunk %s: 401 challenge received, retrying REGISTER with Digest", trunk_name);
        plugmod_resp_object *host_o = config_key_get(section, "host");
        plugmod_resp_object *port_o = config_key_get(section, "port");
        plugmod_resp_object *user_o = config_key_get(section, "username");
        plugmod_resp_object *ua_o = config_key_get(section, "user_agent");
        const char *host = (host_o && (host_o->type == PLUGMOD_RESPT_BULK || host_o->type == PLUGMOD_RESPT_SIMPLE)) ? host_o->u.s : "";
        const char *port = (port_o && (port_o->type == PLUGMOD_RESPT_BULK || port_o->type == PLUGMOD_RESPT_SIMPLE)) ? port_o->u.s : "5060";
        const char *user = (user_o && (user_o->type == PLUGMOD_RESPT_BULK || user_o->type == PLUGMOD_RESPT_SIMPLE)) ? user_o->u.s : "";
        const char *ua = (ua_o && (ua_o->type == PLUGMOD_RESPT_BULK || ua_o->type == PLUGMOD_RESPT_SIMPLE)) ? ua_o->u.s : "";
        plugmod_resp_object *listen_obj = config_key_get("upbx", "listen");
        const char *listen = (listen_obj && (listen_obj->type == PLUGMOD_RESPT_BULK || listen_obj->type == PLUGMOD_RESPT_SIMPLE) && listen_obj->u.s) ? listen_obj->u.s : "0.0.0.0:5060";
        char *req_str = NULL;
        size_t req_len = build_register(host, port, user, password, listen, ua, state, 1, &req_str);
        if (req_len > 0 && req_str && state->reg_res) {
          if (sendto(state->reg_fd, req_str, req_len, 0, state->reg_res->ai_addr, state->reg_res->ai_addrlen) == (ssize_t)req_len)
            state->reg_deadline = time(NULL) + TRUNK_UDP_RECV_TIMEOUT_SEC;
        }
        free(req_str);
        if (host_o) plugmod_resp_free(host_o);
        if (port_o) plugmod_resp_free(port_o);
        if (user_o) plugmod_resp_free(user_o);
        if (ua_o) plugmod_resp_free(ua_o);
        if (listen_obj) plugmod_resp_free(listen_obj);
        if (pw_obj) plugmod_resp_free(pw_obj);
        return;
      }
    }
    if (pw_obj) plugmod_resp_free(pw_obj);
  }
  if (status_code >= 200 && status_code < 300) {
    int refresh = sip_response_contact_expires(buf, buflen);
    if (refresh > TRUNK_REG_REFRESH_LEAD) refresh -= TRUNK_REG_REFRESH_LEAD;
    else refresh = TRUNK_REG_DEFAULT_REFRESH;
    if (refresh < TRUNK_REG_MIN_REFRESH) refresh = TRUNK_REG_MIN_REFRESH;
    state->next_refresh = time(NULL) + refresh;
    state->registered = 1;
    log_info("trunk %s: registered (refresh in %ds)", trunk_name, refresh);
  } else if (status_code > 0) {
    log_warn("trunk %s: REGISTER failed %d", trunk_name, status_code);
    state->registered = 0;
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

void trunk_reg_start(void) {
  log_trace("trunk_reg_start (live config)");
  /* Free any previous state */
  for (size_t i = 0; i < trunk_entries_n; i++) {
    trunk_state_free(&trunk_entries[i].state);
    free(trunk_entries[i].name);
  }
  free(trunk_entries);
  trunk_entries = NULL;
  trunk_entries_n = trunk_entries_cap = 0;
}

void trunk_reg_fill_fds(fd_set *read_set, int *maxfd) {
  for (size_t i = 0; i < trunk_entries_n; i++) {
    if (trunk_entries[i].state.reg_fd >= 0) {
      FD_SET(trunk_entries[i].state.reg_fd, read_set);
      if (trunk_entries[i].state.reg_fd > *maxfd) *maxfd = trunk_entries[i].state.reg_fd;
    }
  }
}

void trunk_reg_poll(fd_set *read_set) {
  time_t now = time(NULL);
  char *buf = malloc(SIP_READ_BUF_SIZE);
  if (!buf) return;
  for (size_t i = 0; i < trunk_entries_n; i++) {
    trunk_state_t *state = &trunk_entries[i].state;
    const char *name = trunk_entries[i].name;
    if (state->reg_fd < 0) continue;
    if (now > state->reg_deadline) {
      if (state->reg_fd >= 0) { close(state->reg_fd); state->reg_fd = -1; }
      if (state->reg_res) { freeaddrinfo(state->reg_res); state->reg_res = NULL; }
      state->registered = 0;
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
    handle_reg_response(name, state, buf, buflen);
  }
  free(buf);
}

PT_THREAD(trunk_reg_pt(struct pt *pt)) {
  PT_BEGIN(pt);
  for (;;) {
    plugmod_resp_object *sections = config_sections_list();
    if (!sections || sections->type != PLUGMOD_RESPT_ARRAY) {
      if (sections) plugmod_resp_free(sections);
      PT_YIELD(pt);
      continue;
    }
    /* Collect current trunk names from config (owned strings) */
    char **names = NULL;
    size_t names_n = 0;
    size_t names_cap = 0;
    for (size_t i = 0; i < sections->u.arr.n; i++) {
      plugmod_resp_object *e = &sections->u.arr.elem[i];
      if ((e->type != PLUGMOD_RESPT_BULK && e->type != PLUGMOD_RESPT_SIMPLE) || !e->u.s) continue;
      if (strncmp(e->u.s, TRUNK_PREFIX, TRUNK_PREFIX_LEN) != 0) continue;
      const char *tail = e->u.s + TRUNK_PREFIX_LEN;
      if (!tail[0]) continue;
      if (names_n >= names_cap) {
        size_t new_cap = names_cap ? names_cap * 2 : 8;
        char **p = realloc(names, new_cap * sizeof(char *));
        if (!p) break;
        names = p;
        names_cap = new_cap;
      }
      names[names_n] = strdup(tail);
      if (names[names_n]) names_n++;
    }
    plugmod_resp_free(sections);

    /* Ensure we have an entry for each configured trunk */
    for (size_t k = 0; k < names_n; k++)
      trunk_find_or_add(names[k]);

    /* Remove entries no longer in config */
    for (size_t i = 0; i < trunk_entries_n; ) {
      int found = 0;
      for (size_t k = 0; k < names_n; k++)
        if (strcmp(trunk_entries[i].name, names[k]) == 0) { found = 1; break; }
      if (!found)
        trunk_remove_at(i);
      else
        i++;
    }
    for (size_t k = 0; k < names_n; k++) free(names[k]);
    free(names);

    time_t now = time(NULL);
    for (size_t i = 0; i < trunk_entries_n; i++) {
      trunk_entry_t *ent = &trunk_entries[i];
      if (ent->state.reg_fd >= 0) continue;
      if (ent->state.next_refresh != 0 && now < ent->state.next_refresh) continue;

      char section[128];
      snprintf(section, sizeof(section), "trunk:%s", ent->name);
      plugmod_resp_object *sec = config_section_get(section);
      if (!sec || sec->type != PLUGMOD_RESPT_ARRAY) {
        if (sec) plugmod_resp_free(sec);
        continue;
      }
      const char *host = plugmod_resp_map_get_string(sec, "host");
      const char *port = plugmod_resp_map_get_string(sec, "port");
      const char *user = plugmod_resp_map_get_string(sec, "username");
      const char *password = plugmod_resp_map_get_string(sec, "password");
      const char *user_agent = plugmod_resp_map_get_string(sec, "user_agent");
      if (!host || !host[0]) {
        plugmod_resp_free(sec);
        continue;
      }
      start_registration(ent->name, host, port ? port : "5060", user, password, user_agent, &ent->state);
      plugmod_resp_free(sec);
    }

    PT_YIELD(pt);
  }
  PT_END(pt);
}

int trunk_reg_is_available(const char *trunk_name) {
  trunk_entry_t *e = trunk_find(trunk_name);
  return e ? e->state.registered : 0;
}
