/*
 * Generic RESP2 API server: TCP listener, connection management, RESP2
 * parsing/writing, command hashmap, authentication with per-user permit
 * checking, and built-in commands (auth, ping, quit, command).
 *
 * Runs as a protothread in the main select() loop.
 */

#include "interface/api/server.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common/resp.h"
#include "common/scheduler.h"
#include "common/socket_util.h"
#include "domain/config.h"
#include "infrastructure/config.h"
#include "rxi/log.h"
#include "tidwall/hashmap.h"

int api_client_pt(int64_t timestamp, struct pt_task *task);

#define API_MAX_CLIENTS 8
#define READ_BUF_SIZE   4096
#define WRITE_BUF_INIT  4096
#define MAX_ARGS        32

struct api_client_state {
  int    fd;
  int   *fds;
  int   *ready_fds;
  int    ready_fd;
  char  *username;
  char   rbuf[READ_BUF_SIZE];
  size_t rlen;
  char  *wbuf;
  size_t wlen;
  size_t wcap;
};

typedef struct api_client_state api_client_t;

typedef struct {
  const char *name;
  char (*func)(api_client_t *c, char **args, int nargs);
} api_cmd_entry;

typedef struct {
  const char   *name;
  domain_cmd_fn func;
} domain_cmd_entry;

static char           *current_listen = NULL;
static struct hashmap *cmd_map        = NULL;
static struct hashmap *domain_cmd_map = NULL;

typedef struct {
  int *server_fds;
  int *ready_fds;
} api_server_udata_t;

bool api_write_raw(api_client_t *c, const void *data, size_t len) {
  if (c->fd < 0) return false;
  if (c->wlen + len > c->wcap) {
    size_t need = c->wlen + len;
    size_t ncap = c->wcap ? c->wcap : WRITE_BUF_INIT;
    while (ncap < need) ncap *= 2;
    char *nb = realloc(c->wbuf, ncap);
    if (!nb) return false;
    c->wbuf = nb;
    c->wcap = ncap;
  }
  memcpy(c->wbuf + c->wlen, data, len);
  c->wlen += len;
  return true;
}

bool api_write_cstr(api_client_t *c, const char *s) {
  return api_write_raw(c, s, strlen(s));
}

bool api_write_ok(api_client_t *c) {
  return api_write_cstr(c, "+OK\r\n");
}

bool api_write_err(api_client_t *c, const char *msg) {
  if (!api_write_cstr(c, "-ERR ")) return false;
  if (!api_write_cstr(c, msg)) return false;
  return api_write_cstr(c, "\r\n");
}

bool api_write_nil(api_client_t *c) {
  return api_write_cstr(c, "$-1\r\n");
}

bool api_write_int(api_client_t *c, int value) {
  char buf[32];
  snprintf(buf, sizeof(buf), ":%d\r\n", value);
  return api_write_cstr(c, buf);
}

bool api_write_array(api_client_t *c, size_t nitems) {
  char buf[32];
  snprintf(buf, sizeof(buf), "*%zu\r\n", nitems);
  return api_write_cstr(c, buf);
}

bool api_write_bulk_cstr(api_client_t *c, const char *s) {
  if (!s) return api_write_nil(c);
  size_t len = strlen(s);
  char   prefix[32];
  snprintf(prefix, sizeof(prefix), "$%zu\r\n", len);
  if (!api_write_cstr(c, prefix)) return false;
  if (!api_write_raw(c, s, len)) return false;
  return api_write_cstr(c, "\r\n");
}

bool api_write_bulk_int(api_client_t *c, int val) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%d", val);
  return api_write_bulk_cstr(c, buf);
}

static void client_close(api_client_t *c) {
  if (c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
  }
  free(c->wbuf);
  c->wbuf = NULL;
  c->wlen = c->wcap = 0;
  c->rlen           = 0;
  free(c->username);
  c->username = NULL;
}

static void client_flush(api_client_t *c) {
  if (c->fd < 0 || c->wlen == 0) return;
  ssize_t n = send(c->fd, c->wbuf, c->wlen, 0);
  if (n > 0) {
    if ((size_t)n < c->wlen) memmove(c->wbuf, c->wbuf + n, c->wlen - (size_t)n);
    c->wlen -= (size_t)n;
  } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    client_close(c);
  }
}

static bool permit_matches(const char *pattern, const char *cmd) {
  size_t plen = strlen(pattern);
  if (plen == 1 && pattern[0] == '*') return true;
  if (plen >= 2 && pattern[plen - 1] == '*') {
    return strncasecmp(pattern, cmd, plen - 1) == 0;
  }
  return strcasecmp(pattern, cmd) == 0;
}

static bool user_has_permit(api_client_t *c, const char *cmd) {
  char        section[128];
  const char *uname = (c->username && c->username[0]) ? c->username : "*";
  snprintf(section, sizeof(section), "user:%s", uname);
  resp_object *sec = resp_map_get(domain_cfg, section);
  if (sec && sec->type == RESPT_ARRAY) {
    for (size_t i = 0; i < sec->u.arr.n; i += 2) {
      if (i + 1 < sec->u.arr.n) {
        resp_object *key = &sec->u.arr.elem[i];
        resp_object *val = &sec->u.arr.elem[i + 1];
        if (key->type == RESPT_BULK && key->u.s && strcmp(key->u.s, "permit") == 0) {
          if (val->type == RESPT_ARRAY) {
            for (size_t j = 0; j < val->u.arr.n; j++) {
              resp_object *p = &val->u.arr.elem[j];
              if (p->type == RESPT_BULK && p->u.s && permit_matches(p->u.s, cmd)) return true;
            }
          } else if (val->type == RESPT_BULK && val->u.s && permit_matches(val->u.s, cmd)) {
            return true;
          }
        }
      }
    }
  }
  if (strcmp(uname, "*") != 0) {
    resp_object *anon = resp_map_get(domain_cfg, "user:*");
    if (anon && anon->type == RESPT_ARRAY) {
      for (size_t i = 0; i < anon->u.arr.n; i += 2) {
        if (i + 1 < anon->u.arr.n) {
          resp_object *key = &anon->u.arr.elem[i];
          resp_object *val = &anon->u.arr.elem[i + 1];
          if (key->type == RESPT_BULK && key->u.s && strcmp(key->u.s, "permit") == 0) {
            if (val->type == RESPT_ARRAY) {
              for (size_t j = 0; j < val->u.arr.n; j++) {
                resp_object *p = &val->u.arr.elem[j];
                if (p->type == RESPT_BULK && p->u.s && permit_matches(p->u.s, cmd)) return true;
              }
            } else if (val->type == RESPT_BULK && val->u.s && permit_matches(val->u.s, cmd)) {
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

static uint64_t cmd_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  const api_cmd_entry *cmd = item;
  return hashmap_sip(cmd->name, strlen(cmd->name), seed0, seed1);
}

static int cmd_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  const api_cmd_entry *ca = a;
  const api_cmd_entry *cb = b;
  return strcasecmp(ca->name, cb->name);
}

void api_register_cmd(const char *name, char (*func)(api_client_t *, char **, int)) {
  if (!cmd_map) cmd_map = hashmap_new(sizeof(api_cmd_entry), 0, 0, 0, cmd_hash, cmd_compare, NULL, NULL);
  hashmap_set(cmd_map, &(api_cmd_entry){.name = name, .func = func});
  log_trace("api: registered command '%s'", name);
}

static uint64_t domain_cmd_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  const domain_cmd_entry *cmd = item;
  return hashmap_sip(cmd->name, strlen(cmd->name), seed0, seed1);
}

static int domain_cmd_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  const domain_cmd_entry *ca = a;
  const domain_cmd_entry *cb = b;
  return strcasecmp(ca->name, cb->name);
}

void api_register_domain_cmd(const char *name, domain_cmd_fn func) {
  if (!domain_cmd_map)
    domain_cmd_map = hashmap_new(sizeof(domain_cmd_entry), 0, 0, 0, domain_cmd_hash, domain_cmd_compare, NULL, NULL);
  hashmap_set(domain_cmd_map, &(domain_cmd_entry){.name = name, .func = func});
  log_trace("api: registered domain command '%s'", name);
}

static char cmdAUTH(api_client_t *c, char **args, int nargs) {
  if (nargs != 3) {
    api_write_err(c,
                  "wrong number of arguments for 'auth' command (AUTH "
                  "username password)");
    return 1;
  }
  const char *uname = args[1];
  const char *pass  = args[2];
  char        section[128];
  snprintf(section, sizeof(section), "user:%s", uname);
  resp_object *sec    = resp_map_get(domain_cfg, section);
  const char  *secret = sec ? resp_map_get_string(sec, "secret") : NULL;
  if (secret && pass && strcmp(secret, pass) == 0) {
    free(c->username);
    c->username = strdup(uname);
    if (c->username) {
      log_debug("api: client authenticated as '%s'", uname);
      return api_write_ok(c) ? 1 : 0;
    }
  }
  return api_write_err(c, "invalid credentials") ? 1 : 0;
}

static char cmdPING(api_client_t *c, char **args, int nargs) {
  (void)args;
  if (nargs == 1) return api_write_cstr(c, "+PONG\r\n") ? 1 : 0;
  if (nargs == 2) return api_write_bulk_cstr(c, args[1]) ? 1 : 0;
  return api_write_err(c, "wrong number of arguments for 'ping' command") ? 1 : 0;
}

static char cmdQUIT(api_client_t *c, char **args, int nargs) {
  (void)args;
  (void)nargs;
  api_write_ok(c);
  return 0;
}

static bool is_builtin(const char *name);

static char cmdCOMMAND(api_client_t *c, char **args, int nargs) {
  (void)args;
  if (!cmd_map && !domain_cmd_map) return api_write_array(c, 0) ? 1 : 0;

  resp_object *result = resp_array_init();
  if (!result) return 0;

  if (domain_cmd_map) {
    size_t iter = 0;
    void  *item;
    while (hashmap_iter(domain_cmd_map, &iter, &item)) {
      const domain_cmd_entry *e = item;
      if (!user_has_permit(c, e->name)) continue;

      resp_array_append_bulk(result, e->name);
      resp_object *meta = resp_array_init();
      if (!meta) {
        resp_free(result);
        return 0;
      }
      resp_array_append_bulk(meta, "summary");
      resp_array_append_bulk(meta, "UPBX command");
      resp_array_append_obj(result, meta);
    }
  }

  if (cmd_map) {
    size_t iter = 0;
    void  *item;
    while (hashmap_iter(cmd_map, &iter, &item)) {
      const api_cmd_entry *e = item;
      if (!is_builtin(e->name) && !user_has_permit(c, e->name)) continue;

      resp_array_append_bulk(result, e->name);
      resp_object *meta = resp_array_init();
      if (!meta) {
        resp_free(result);
        return 0;
      }
      resp_array_append_bulk(meta, "summary");
      resp_array_append_bulk(meta, "UPBX command");
      resp_array_append_obj(result, meta);
    }
  }

  char  *out_buf = NULL;
  size_t out_len = 0;
  if (resp_serialize(result, &out_buf, &out_len) != 0 || !out_buf) {
    resp_free(result);
    return 0;
  }
  resp_free(result);

  api_write_raw(c, out_buf, out_len);
  free(out_buf);
  return 1;
}

static void init_builtins(void) {
  api_register_cmd("auth", cmdAUTH);
  api_register_cmd("ping", cmdPING);
  api_register_cmd("quit", cmdQUIT);
  api_register_cmd("command", cmdCOMMAND);
}

static bool is_builtin(const char *name) {
  return (strcasecmp(name, "auth") == 0 || strcasecmp(name, "ping") == 0 || strcasecmp(name, "quit") == 0 ||
          strcasecmp(name, "command") == 0);
}

static void dispatch_command(api_client_t *c, char **args, int nargs) {
  if (nargs <= 0) return;

  for (char *p = args[0]; *p; p++) *p = (char)tolower((unsigned char)*p);

  const domain_cmd_entry *dcmd = hashmap_get(domain_cmd_map, &(domain_cmd_entry){.name = args[0]});
  if (dcmd) {
    if (!is_builtin(args[0])) {
      if (!user_has_permit(c, args[0])) {
        api_write_err(c, "no permission");
        return;
      }
    }

    resp_object *domain_args = resp_array_init();
    if (!domain_args) return;

    for (int i = 0; i < nargs; i++) {
      resp_array_append_bulk(domain_args, args[i]);
    }

    resp_object *result = dcmd->func(args[0], domain_args);
    resp_free(domain_args);

    if (!result) {
      api_write_err(c, "command failed");
      return;
    }

    char  *out_buf = NULL;
    size_t out_len = 0;
    if (resp_serialize(result, &out_buf, &out_len) != 0 || !out_buf) {
      resp_free(result);
      api_write_err(c, "command failed");
      return;
    }
    resp_free(result);

    api_write_raw(c, out_buf, out_len);
    free(out_buf);
    return;
  }

  const api_cmd_entry *cmd = hashmap_get(cmd_map, &(api_cmd_entry){.name = args[0]});
  if (!cmd) {
    api_write_err(c, "unknown command");
    return;
  }

  if (!is_builtin(args[0])) {
    if (!user_has_permit(c, args[0])) {
      api_write_err(c, "no permission");
      return;
    }
  }

  char result = cmd->func(c, args, nargs);
  if (!result) {
    client_flush(c);
    client_close(c);
  }
}

static int *create_listen_socket(const char *listen_addr) {
  const char  *default_port = "6379";
  resp_object *api_sec      = resp_map_get(domain_cfg, "api");
  if (api_sec) {
    const char *cfg_port = resp_map_get_string(api_sec, "port");
    if (cfg_port && cfg_port[0]) default_port = cfg_port;
  }

  if (listen_addr && strncmp(listen_addr, "unix://", 7) == 0) {
    const char *socket_path  = listen_addr + 7;
    const char *socket_owner = api_sec ? resp_map_get_string(api_sec, "socket_owner") : NULL;
    int        *fds          = unix_listen(socket_path, SOCK_STREAM, socket_owner);
    if (!fds) {
      return NULL;
    }
    log_info("api: listening on %s", listen_addr);
    return fds;
  }

  int *fds = tcp_listen(listen_addr, NULL, default_port);
  if (!fds) {
    return NULL;
  }
  log_info("api: listening on %s", listen_addr);
  return fds;
}

static void handle_accept(int ready_fd) {
  struct sockaddr_storage addr;
  socklen_t               addrlen = sizeof(addr);
  int                     fd      = accept(ready_fd, (struct sockaddr *)&addr, &addrlen);
  if (fd < 0) return;
  set_socket_nonblocking(fd, 1);

  api_client_t *state = calloc(1, sizeof(*state));
  if (!state) {
    const char *msg = "-ERR out of memory\r\n";
    send(fd, msg, strlen(msg), 0);
    close(fd);
    return;
  }
  state->fd = fd;

  sched_create(api_client_pt, state);
  log_trace("api: accepted connection, spawned client pt");
}

int api_server_pt(int64_t timestamp, struct pt_task *task) {
  (void)timestamp;
  api_server_udata_t *udata = task->udata;

  if (!udata) {
    udata = calloc(1, sizeof(api_server_udata_t));
    if (!udata) {
      return SCHED_ERROR;
    }
    task->udata = udata;
  }

  if (udata->server_fds == NULL) {
    resp_object *api_sec  = resp_map_get(domain_cfg, "api");
    resp_object *addr_arr = api_sec ? resp_map_get(api_sec, "address") : NULL;

    if (!addr_arr || addr_arr->type != RESPT_ARRAY || addr_arr->u.arr.n == 0) {
      return SCHED_RUNNING;
    }

    init_builtins();

    int **fd_arrays = malloc(sizeof(int *) * addr_arr->u.arr.n);
    int valid_count = 0;

    for (size_t i = 0; i < addr_arr->u.arr.n; i++) {
      const char *addr = addr_arr->u.arr.elem[i].u.s;
      if (!addr || !addr[0]) {
        fd_arrays[i] = NULL;
        continue;
      }
      fd_arrays[i] = create_listen_socket(addr);
      if (fd_arrays[i] && fd_arrays[i][0] > 0) {
        valid_count++;
      }
    }

    if (valid_count > 0) {
      udata->server_fds = merge_fd_arrays(fd_arrays, addr_arr->u.arr.n);
    }

    free(fd_arrays);

    if (!udata->server_fds || udata->server_fds[0] == 0) {
      log_fatal("api: failed to listen on any address");
      return SCHED_ERROR;
    }
  }

  if (udata->server_fds && udata->server_fds[0] > 0) {
    int ready_fd = sched_has_data(udata->server_fds);
    if (ready_fd >= 0) {
      handle_accept(ready_fd);
    }
  }

  return SCHED_RUNNING;
}

int api_client_pt(int64_t timestamp, struct pt_task *task) {
  (void)timestamp;
  api_client_t *state = task->udata;

  if (!state->fds) {
    state->fds = malloc(sizeof(int) * 2);
    if (!state->fds) {
      free(state);
      return SCHED_DONE;
    }
    state->fds[0] = 1;
    state->fds[1] = state->fd;
  }

  int ready_fd = sched_has_data(state->fds);
  if (ready_fd < 0) {
    return SCHED_RUNNING;
  }

  if (ready_fd != state->fd) {
    return SCHED_RUNNING;
  }

  if (state->rlen >= READ_BUF_SIZE) {
    goto cleanup;
  }

  ssize_t n = recv(state->fd, state->rbuf + state->rlen, READ_BUF_SIZE - state->rlen, 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return SCHED_RUNNING;
    }
    goto cleanup;
  }
  if (n == 0) {
    goto cleanup;
  }
  state->rlen += (size_t)n;

  resp_object *cmd = NULL;
  int consumed = resp_read_buf(state->rbuf, state->rlen, &cmd);
  if (consumed > 0) {
    memmove(state->rbuf, state->rbuf + consumed, state->rlen - consumed);
    state->rlen -= consumed;
  } else if (consumed < 0) {
    return SCHED_RUNNING;
  } else {
    return SCHED_RUNNING;
  }

  if (!cmd) {
    return SCHED_RUNNING;
  }

  if (cmd->type != RESPT_ARRAY || cmd->u.arr.n == 0) {
    resp_free(cmd);
    api_write_err(state, "Protocol error");
    client_flush(state);
    return SCHED_RUNNING;
  }

  char *args[MAX_ARGS];
  int   nargs = 0;
  for (size_t i = 0; i < cmd->u.arr.n && nargs < MAX_ARGS; i++) {
    resp_object *elem = &cmd->u.arr.elem[i];
    if (elem->type == RESPT_BULK && elem->u.s) {
      args[nargs++] = elem->u.s;
      elem->u.s     = NULL;
    } else if (elem->type == RESPT_SIMPLE) {
      args[nargs++] = elem->u.s ? elem->u.s : "";
    }
  }

  if (nargs > 0) {
    dispatch_command(state, args, nargs);
  }

  for (int j = 0; j < nargs; j++) {
    free(args[j]);
  }
  resp_free(cmd);

  client_flush(state);

  if (state->fd < 0) {
    goto cleanup;
  }

  return SCHED_RUNNING;

cleanup:
  if (state->fd >= 0) {
    close(state->fd);
  }
  free(state->fds);
  free(state->wbuf);
  free(state->username);
  free(state);
  return SCHED_DONE;
}
