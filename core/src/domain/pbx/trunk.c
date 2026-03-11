#include "domain/pbx/trunk.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/digest_auth.h"
#include "common/resp.h"
#include "common/scheduler.h"
#include "common/socket_util.h"
#include "domain/config.h"
#include "domain/pbx/sip_builder.h"
#include "domain/pbx/sip_parser.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

#define TRUNK_EXPIRES_DEFAULT 300
#define TRUNK_BACKOFF_MAX     60
#define TRUNK_RESPONSE_TIMEOUT 5

/* ------------------------------------------------------------------ */
/* trunk registry: simple linked list                                  */
/* ------------------------------------------------------------------ */

typedef struct trunk_entry {
  struct trunk_entry *next;
  trunk_config_t      cfg;
  pt_task_t          *task;  /* scheduler handle so we can remove it */
} trunk_entry_t;

static trunk_entry_t *trunk_list = NULL;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static int strcmp_null(const char *a, const char *b) {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  return strcmp(a, b);
}

static void trunk_config_free_fields(trunk_config_t *cfg) {
  if (!cfg) return;
  free(cfg->name);
  free(cfg->protocol);
  free(cfg->host);
  free(cfg->username);
  free(cfg->password);
  free(cfg->cid);
  for (size_t i = 0; i < cfg->did_count; i++) {
    free(cfg->dids[i]);
  }
  free(cfg->dids);
  for (size_t i = 0; i < cfg->group_count; i++) {
    free(cfg->groups[i]);
  }
  free(cfg->groups);
  memset(cfg, 0, sizeof(*cfg));
}

static void trunk_state_free(trunk_state_t *s) {
  if (!s) return;
  if (s->fd > 0) close(s->fd);
  free(s->nonce);
  free(s->realm);
  free(s);
}

static int trunk_resolve_remote(trunk_state_t *s) {
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", s->cfg->port);

  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  int rc = getaddrinfo(s->cfg->host, port_str, &hints, &res);
  if (rc != 0 || !res) {
    log_error("trunk[%s]: DNS resolution failed for %s:%s", s->cfg->name, s->cfg->host, port_str);
    return -1;
  }

  memcpy(&s->remote_addr, res->ai_addr, res->ai_addrlen);
  s->remote_addr_len = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}

static void trunk_generate_call_id(trunk_state_t *s) {
  snprintf(s->call_id, sizeof(s->call_id), "trunk-%s-%08x%08x",
           s->cfg->name, (unsigned int)rand(), (unsigned int)time(NULL));
}

/* ------------------------------------------------------------------ */
/* build and send REGISTER                                             */
/* ------------------------------------------------------------------ */

static void trunk_send_register(trunk_state_t *s) {
  s->cseq++;

  /* Build From / To : sip:username@host */
  char from_to[256];
  snprintf(from_to, sizeof(from_to), "<sip:%s@%s>;tag=trunk-%s",
           s->cfg->username ? s->cfg->username : "",
           s->cfg->host,
           s->cfg->name);

  char to_hdr[256];
  snprintf(to_hdr, sizeof(to_hdr), "<sip:%s@%s>",
           s->cfg->username ? s->cfg->username : "",
           s->cfg->host);

  /* Request-URI */
  char request_uri[256];
  snprintf(request_uri, sizeof(request_uri), "sip:%s:%d",
           s->cfg->host, s->cfg->port);

  /* Via */
  char via[256];
  snprintf(via, sizeof(via), "SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK%08x%08x;rport",
           (unsigned int)rand(), (unsigned int)time(NULL));

  /* Contact */
  char contact[256];
  snprintf(contact, sizeof(contact), "<sip:%s@0.0.0.0:5060>",
           s->cfg->username ? s->cfg->username : "");

  /* Build the base message using a fake sip_message_t template */
  sip_message_t tmpl;
  memset(&tmpl, 0, sizeof(tmpl));
  tmpl.method      = "REGISTER";
  tmpl.uri         = request_uri;
  tmpl.via         = via;
  tmpl.from        = from_to;
  tmpl.to          = to_hdr;
  tmpl.call_id     = s->call_id;
  tmpl.cseq        = s->cseq;
  tmpl.cseq_method = "REGISTER";

  /* Extra headers: Contact + Expires + optional Authorization */
  char extra[1024];
  int  extra_off = 0;

  extra_off += snprintf(extra + extra_off, sizeof(extra) - extra_off,
                        "Contact: %s\r\nExpires: %d\r\nUser-Agent: upbx-" UPBX_VERSION_STR,
                        contact, TRUNK_EXPIRES_DEFAULT);

  if (s->auth_challenged && s->nonce && s->realm && s->cfg->username && s->cfg->password) {
    char *auth_uri = request_uri;

    HASHHEX ha1, ha2, response;
    digest_calc_ha1(s->cfg->username, s->realm, s->cfg->password, ha1);
    digest_calc_ha2("REGISTER", auth_uri, ha2);
    digest_calc_response(ha1, s->nonce, ha2, response);

    extra_off += snprintf(extra + extra_off, sizeof(extra) - extra_off,
                          "\r\nAuthorization: Digest username=\"%s\", realm=\"%s\", "
                          "nonce=\"%s\", uri=\"%s\", response=\"%s\"",
                          s->cfg->username, s->realm, s->nonce, auth_uri, response);
  }

  char *msg = sip_build_message(0, NULL, &tmpl, extra, NULL);
  if (!msg) {
    log_error("trunk[%s]: failed to build REGISTER", s->cfg->name);
    return;
  }

  ssize_t sent = sendto(s->fd, msg, strlen(msg), 0,
                         (struct sockaddr *)&s->remote_addr, s->remote_addr_len);
  if (sent < 0) {
    log_error("trunk[%s]: sendto failed", s->cfg->name);
  } else {
    log_debug("trunk[%s]: sent REGISTER (cseq=%d, auth=%d)",
              s->cfg->name, s->cseq, s->auth_challenged);
  }

  free(msg);
}

/* ------------------------------------------------------------------ */
/* handle incoming response                                            */
/* ------------------------------------------------------------------ */

static char *parse_auth_param(const char *hdr, const char *param) {
  if (!hdr || !param) return NULL;
  const char *p = strstr(hdr, param);
  if (!p) return NULL;
  p += strlen(param);
  while (*p == ' ' || *p == '=' || *p == '"') p++;
  const char *end = p;
  while (*end && *end != '"' && *end != ',') end++;
  if (end <= p) return NULL;
  return strndup(p, (size_t)(end - p));
}

static void trunk_handle_response(trunk_state_t *s, time_t now) {
  sip_message_t *msg = sip_parse(s->recv_buf, strlen(s->recv_buf));
  if (!msg) return;

  /* Verify Call-ID matches */
  if (!msg->call_id || strcmp(msg->call_id, s->call_id) != 0) {
    sip_message_free(msg);
    return;
  }

  int status = sip_response_status_code(msg);

  if (status == 200) {
    /* Success - extract expires */
    int expires = TRUNK_EXPIRES_DEFAULT;
    if (msg->contact) {
      const char *exp_str = strstr(msg->contact, "expires=");
      if (exp_str) expires = atoi(exp_str + 8);
    }
    if (expires <= 0) expires = TRUNK_EXPIRES_DEFAULT;

    s->registered_at   = now;
    s->expires_seconds = expires;
    s->retry_count     = 0;
    s->auth_challenged = 0;

    /* Re-register at 80% of expiry */
    s->next_register = now + (time_t)(expires * 4 / 5);

    log_info("trunk[%s]: registered (expires=%d, next in %ds)",
             s->cfg->name, expires, (int)(s->next_register - now));

  } else if (status == 401) {
    /* Authentication challenge */
    const char *www_auth = msg->www_authenticate;
    if (www_auth) {
      free(s->realm);
      free(s->nonce);
      s->realm = parse_auth_param(www_auth, "realm");
      s->nonce = parse_auth_param(www_auth, "nonce");
    }

    if (s->auth_challenged) {
      /* Already tried auth and got 401 again - credentials are wrong */
      log_error("trunk[%s]: authentication failed (bad credentials?)", s->cfg->name);
      s->auth_challenged = 0;
      s->retry_count++;
      int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
      if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
      s->next_register = now + (time_t)backoff;
    } else {
      /* First challenge - retry immediately with auth */
      log_debug("trunk[%s]: received 401, retrying with auth", s->cfg->name);
      s->auth_challenged = 1;
      s->next_register   = now;
    }

  } else {
    /* Other error - backoff */
    log_warn("trunk[%s]: REGISTER returned %d", s->cfg->name, status);
    s->auth_challenged = 0;
    s->retry_count++;
    int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
    if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
    s->next_register = now + (time_t)backoff;
  }

  sip_message_free(msg);
}

/* ------------------------------------------------------------------ */
/* protothread                                                         */
/* ------------------------------------------------------------------ */

int trunk_register_pt(int64_t timestamp, struct pt_task *task) {
  trunk_state_t *s = (trunk_state_t *)task->udata;
  time_t now = (time_t)(timestamp / 1000);

  if (!s || !s->cfg) {
    log_error("trunk: protothread has no state");
    return SCHED_ERROR;
  }

  /* Create socket on first run */
  if (s->fd <= 0) {
    if (trunk_resolve_remote(s) != 0) {
      s->retry_count++;
      int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
      if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
      s->next_register = now + (time_t)backoff;
      return SCHED_RUNNING;
    }

    int af = s->remote_addr.ss_family;
    s->fd = socket(af, SOCK_DGRAM, 0);
    if (s->fd < 0) {
      log_error("trunk[%s]: failed to create socket", s->cfg->name);
      s->fd = 0;
      s->retry_count++;
      int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
      if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
      s->next_register = now + (time_t)backoff;
      return SCHED_RUNNING;
    }

    set_socket_nonblocking(s->fd, 1);
    s->fds[0] = 1;
    s->fds[1] = s->fd;

    trunk_generate_call_id(s);
    s->next_register = now; /* register immediately */

    log_info("trunk[%s]: socket ready (fd=%d)", s->cfg->name, s->fd);
  }

  /* Check for incoming data */
  int ready = sched_has_data(s->fds);
  if (ready > 0) {
    struct sockaddr_storage from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t n = recvfrom(s->fd, s->recv_buf, sizeof(s->recv_buf) - 1, 0,
                          (struct sockaddr *)&from_addr, &from_len);
    if (n > 0) {
      s->recv_buf[n] = '\0';
      log_trace("trunk[%s]: received %zd bytes", s->cfg->name, n);
      trunk_handle_response(s, now);
    }
  }

  /* Time to (re)register? */
  if (now >= s->next_register) {
    trunk_send_register(s);
    /* Set a response timeout - if no response comes, we'll retry */
    s->next_register = now + TRUNK_RESPONSE_TIMEOUT;
  }

  return SCHED_RUNNING;
}

/* ------------------------------------------------------------------ */
/* config parsing                                                      */
/* ------------------------------------------------------------------ */

static trunk_config_t *trunk_parse_section(const char *name, resp_object *sec) {
  trunk_config_t *cfg = calloc(1, sizeof(trunk_config_t));
  if (!cfg) return NULL;

  cfg->name = strdup(name);

  /* Parse address URL */
  resp_object *addr_arr = resp_map_get(sec, "address");
  const char *addr_str = NULL;
  if (addr_arr && addr_arr->type == RESPT_ARRAY && addr_arr->u.arr.n > 0) {
    addr_str = addr_arr->u.arr.elem[0].u.s;
  }
  if (!addr_str) {
    addr_str = resp_map_get_string(sec, "address");
  }

  if (!addr_str) {
    log_error("trunk[%s]: missing 'address' field", name);
    trunk_config_free_fields(cfg);
    free(cfg);
    return NULL;
  }

  struct parsed_url *url = parse_url(addr_str);
  if (!url) {
    log_error("trunk[%s]: failed to parse address '%s': %s", name, addr_str, parse_url_last_error());
    trunk_config_free_fields(cfg);
    free(cfg);
    return NULL;
  }

  cfg->protocol = url->scheme   ? strdup(url->scheme)   : strdup("udp");
  cfg->host     = url->host     ? strdup(url->host)     : NULL;
  cfg->port     = url->port     ? atoi(url->port)       : 5060;
  cfg->username = url->username ? strdup(url->username) : NULL;
  cfg->password = url->password ? strdup(url->password) : NULL;
  parsed_url_free(url);

  if (!cfg->host || !cfg->host[0]) {
    log_error("trunk[%s]: address has no host", name);
    trunk_config_free_fields(cfg);
    free(cfg);
    return NULL;
  }

  /* CID (single value) */
  const char *cid = resp_map_get_string(sec, "cid");
  cfg->cid = cid ? strdup(cid) : NULL;

  /* DIDs (repeatable array) */
  resp_object *did_arr = resp_map_get(sec, "did");
  if (did_arr && did_arr->type == RESPT_ARRAY) {
    cfg->did_count = did_arr->u.arr.n;
    cfg->dids = calloc(cfg->did_count, sizeof(char *));
    for (size_t i = 0; i < cfg->did_count; i++) {
      if (did_arr->u.arr.elem[i].type == RESPT_BULK || did_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
        cfg->dids[i] = strdup(did_arr->u.arr.elem[i].u.s);
      }
    }
  }

  /* Groups (repeatable array) */
  resp_object *group_arr = resp_map_get(sec, "group");
  if (group_arr && group_arr->type == RESPT_ARRAY) {
    cfg->group_count = group_arr->u.arr.n;
    cfg->groups = calloc(cfg->group_count, sizeof(char *));
    for (size_t i = 0; i < cfg->group_count; i++) {
      if (group_arr->u.arr.elem[i].type == RESPT_BULK || group_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
        cfg->groups[i] = strdup(group_arr->u.arr.elem[i].u.s);
      }
    }
  }

  log_info("trunk[%s]: parsed config host=%s port=%d user=%s cid=%s dids=%zu groups=%zu",
           name, cfg->host, cfg->port,
           cfg->username ? cfg->username : "(none)",
           cfg->cid ? cfg->cid : "(none)",
           cfg->did_count, cfg->group_count);

  return cfg;
}

/* ------------------------------------------------------------------ */
/* spawn / teardown                                                    */
/* ------------------------------------------------------------------ */

static void trunk_spawn(trunk_config_t *cfg) {
  trunk_state_t *state = calloc(1, sizeof(trunk_state_t));
  state->cfg = cfg;

  sched_create(trunk_register_pt, state);

  /* Walk the scheduler list to find the task we just created
   * (it's prepended as head) so we can store the handle. */
  extern pt_task_t *pt_first;
  trunk_entry_t *entry = trunk_list;
  while (entry) {
    if (&entry->cfg == cfg) {
      entry->task = pt_first;
      break;
    }
    entry = entry->next;
  }
}

static void trunk_teardown(trunk_entry_t *entry) {
  if (entry->task) {
    trunk_state_t *s = (trunk_state_t *)entry->task->udata;
    trunk_state_free(s);
    entry->task->udata = NULL;
    sched_remove(entry->task);
    entry->task = NULL;
  }
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

void pbx_trunk_init(void) {
  if (!domain_cfg) return;

  /* Iterate config map for "trunk:*" keys */
  for (size_t i = 0; i + 1 < domain_cfg->u.arr.n; i += 2) {
    if (domain_cfg->u.arr.elem[i].type != RESPT_BULK &&
        domain_cfg->u.arr.elem[i].type != RESPT_SIMPLE) continue;

    const char *key = domain_cfg->u.arr.elem[i].u.s;
    if (!key || strncmp(key, "trunk:", 6) != 0) continue;

    const char *trunk_name = key + 6;
    resp_object *sec = resp_map_get(domain_cfg, key);
    if (!sec || sec->type != RESPT_ARRAY) continue;

    trunk_config_t *cfg = trunk_parse_section(trunk_name, sec);
    if (!cfg) continue;

    /* Add to registry */
    trunk_entry_t *entry = calloc(1, sizeof(trunk_entry_t));
    entry->cfg  = *cfg;  /* struct copy */
    free(cfg);            /* free the container, fields are now in entry->cfg */
    entry->next = trunk_list;
    trunk_list  = entry;

    /* Spawn protothread */
    trunk_spawn(&entry->cfg);
  }
}

void pbx_trunk_shutdown(void) {
  trunk_entry_t *entry = trunk_list;
  while (entry) {
    trunk_entry_t *next = entry->next;
    trunk_teardown(entry);
    trunk_config_free_fields(&entry->cfg);
    free(entry);
    entry = next;
  }
  trunk_list = NULL;
}

void pbx_trunk_reload(void) {
  if (!domain_cfg) return;

  /* Build a set of trunk names from the new config */
  /* For each existing trunk, check if config changed; for new ones, spawn */

  /* Pass 1: mark existing entries, detect changes */
  trunk_entry_t *entry = trunk_list;
  while (entry) {
    char key[64];
    snprintf(key, sizeof(key), "trunk:%s", entry->cfg.name);
    resp_object *sec = resp_map_get(domain_cfg, key);

    if (!sec || sec->type != RESPT_ARRAY) {
      /* Trunk removed from config - teardown */
      log_info("trunk[%s]: removed from config, stopping", entry->cfg.name);
      trunk_teardown(entry);
      entry = entry->next;
      continue;
    }

    /* Re-parse and compare address (the critical field) */
    trunk_config_t *new_cfg = trunk_parse_section(entry->cfg.name, sec);
    if (!new_cfg) {
      trunk_teardown(entry);
      entry = entry->next;
      continue;
    }

    int changed = 0;
    if (strcmp_null(entry->cfg.host, new_cfg->host) != 0) changed = 1;
    if (entry->cfg.port != new_cfg->port) changed = 1;
    if (strcmp_null(entry->cfg.username, new_cfg->username) != 0) changed = 1;
    if (strcmp_null(entry->cfg.password, new_cfg->password) != 0) changed = 1;

    if (changed) {
      log_info("trunk[%s]: config changed, restarting", entry->cfg.name);
      trunk_teardown(entry);
      trunk_config_free_fields(&entry->cfg);
      entry->cfg = *new_cfg;
      free(new_cfg);
      trunk_spawn(&entry->cfg);
    } else {
      /* Update non-critical fields in place */
      free(entry->cfg.cid);
      entry->cfg.cid = new_cfg->cid;
      new_cfg->cid = NULL;

      for (size_t i = 0; i < entry->cfg.did_count; i++) free(entry->cfg.dids[i]);
      free(entry->cfg.dids);
      entry->cfg.dids      = new_cfg->dids;
      entry->cfg.did_count = new_cfg->did_count;
      new_cfg->dids      = NULL;
      new_cfg->did_count = 0;

      for (size_t i = 0; i < entry->cfg.group_count; i++) free(entry->cfg.groups[i]);
      free(entry->cfg.groups);
      entry->cfg.groups      = new_cfg->groups;
      entry->cfg.group_count = new_cfg->group_count;
      new_cfg->groups      = NULL;
      new_cfg->group_count = 0;

      trunk_config_free_fields(new_cfg);
      free(new_cfg);
    }

    entry = entry->next;
  }

  /* Pass 2: find new trunks not in the list */
  for (size_t i = 0; i + 1 < domain_cfg->u.arr.n; i += 2) {
    if (domain_cfg->u.arr.elem[i].type != RESPT_BULK &&
        domain_cfg->u.arr.elem[i].type != RESPT_SIMPLE) continue;

    const char *key = domain_cfg->u.arr.elem[i].u.s;
    if (!key || strncmp(key, "trunk:", 6) != 0) continue;

    const char *trunk_name = key + 6;

    /* Check if already in list */
    int found = 0;
    trunk_entry_t *e = trunk_list;
    while (e) {
      if (e->cfg.name && strcmp(e->cfg.name, trunk_name) == 0) {
        found = 1;
        break;
      }
      e = e->next;
    }
    if (found) continue;

    resp_object *sec = resp_map_get(domain_cfg, key);
    if (!sec || sec->type != RESPT_ARRAY) continue;

    trunk_config_t *cfg = trunk_parse_section(trunk_name, sec);
    if (!cfg) continue;

    trunk_entry_t *new_entry = calloc(1, sizeof(trunk_entry_t));
    new_entry->cfg  = *cfg;
    free(cfg);
    new_entry->next = trunk_list;
    trunk_list      = new_entry;

    trunk_spawn(&new_entry->cfg);
    log_info("trunk[%s]: new trunk detected, starting", trunk_name);
  }

  /* Pass 3: remove entries that were torn down (no task) and have no config */
  trunk_entry_t **pp = &trunk_list;
  while (*pp) {
    trunk_entry_t *cur = *pp;
    if (!cur->task) {
      char key[64];
      snprintf(key, sizeof(key), "trunk:%s", cur->cfg.name);
      resp_object *sec = resp_map_get(domain_cfg, key);
      if (!sec) {
        *pp = cur->next;
        trunk_config_free_fields(&cur->cfg);
        free(cur);
        continue;
      }
    }
    pp = &(*pp)->next;
  }
}
