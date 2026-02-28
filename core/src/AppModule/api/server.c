/*
 * Generic RESP2 API server: TCP listener, connection management, RESP2
 * parsing/writing, command hashmap, authentication with per-user permit
 * checking, and built-in commands (auth, ping, quit, command).
 *
 * Runs as a protothread in the main select() loop.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "rxi/log.h"
#include "tidwall/hashmap.h"
#include "SchedulerModule/protothreads.h"
#include "SchedulerModule/scheduler.h"
#include "common/socket_util.h"
#include "config.h"
#include "server.h"

struct pt_task;
PT_THREAD(api_client_pt(struct pt *pt, int64_t timestamp, struct pt_task *task));

/* Constants */

#define API_MAX_CLIENTS   8
#define READ_BUF_SIZE     4096
#define WRITE_BUF_INIT    4096
#define MAX_ARGS          32

/* Per-client connection state (stored in pt udata) */

struct api_client_state {
  int       fd;
  int      *fds;
  char     *username;
  char      rbuf[READ_BUF_SIZE];
  size_t    rlen;
  char     *wbuf;
  size_t    wlen;
  size_t    wcap;
};

typedef struct api_client_state api_client_t;

/* Command entry */

typedef struct {
  const char  *name;
  char       (*func)(api_client_t *c, char **args, int nargs);
} api_cmd_entry;

/* Module state */

static char     *current_listen = NULL;
static time_t   next_listen_check = 0;
static struct hashmap  *cmd_map = NULL;

/* Write helpers */

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
  char prefix[32];
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

/* Client lifecycle */

static void client_close(api_client_t *c) {
  if (c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
  }
  free(c->wbuf);
  c->wbuf = NULL;
  c->wlen = c->wcap = 0;
  c->rlen = 0;
  free(c->username);
  c->username = NULL;
}

static void client_flush(api_client_t *c) {
  if (c->fd < 0 || c->wlen == 0) return;
  ssize_t n = send(c->fd, c->wbuf, c->wlen, 0);
  if (n > 0) {
    if ((size_t)n < c->wlen)
      memmove(c->wbuf, c->wbuf + n, c->wlen - (size_t)n);
    c->wlen -= (size_t)n;
  } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    client_close(c);
  }
}

/* RESP2 inline (telnet) parser */

static int parse_inline(const char *line, size_t len, char **args, int max_args) {
  int nargs = 0;
  const char *p = line;
  const char *end = line + len;
  while (p < end && nargs < max_args) {
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end) break;
    const char *start;
    const char *tok_end;
    if (*p == '"' || *p == '\'') {
      char quote = *p++;
      start = p;
      while (p < end && *p != quote) p++;
      tok_end = p;
      if (p < end) p++;
    } else {
      start = p;
      while (p < end && *p != ' ' && *p != '\t') p++;
      tok_end = p;
    }
    size_t tlen = (size_t)(tok_end - start);
    char *arg = malloc(tlen + 1);
    if (!arg) return -1;
    memcpy(arg, start, tlen);
    arg[tlen] = '\0';
    args[nargs++] = arg;
  }
  return nargs;
}

/* RESP2 multibulk parser */

static int parse_resp_command(api_client_t *c, char **args, int max_args, int *nargs) {
  *nargs = 0;
  if (c->rlen == 0) return 0;

  if (c->rbuf[0] != '*') {
    char *nl = memchr(c->rbuf, '\n', c->rlen);
    if (!nl) return 0;
    size_t line_len = (size_t)(nl - c->rbuf);
    size_t trim = line_len;
    if (trim > 0 && c->rbuf[trim - 1] == '\r') trim--;
    int n = parse_inline(c->rbuf, trim, args, max_args);
    if (n < 0) return -1;
    *nargs = n;
    size_t consumed = line_len + 1;
    c->rlen -= consumed;
    if (c->rlen > 0) memmove(c->rbuf, c->rbuf + consumed, c->rlen);
    return n > 0 ? 1 : 0;
  }

  size_t pos = 0;
  char *nl = memchr(c->rbuf + pos, '\n', c->rlen - pos);
  if (!nl) return 0;
  int count = atoi(c->rbuf + 1);
  if (count <= 0 || count > max_args) return -1;
  pos = (size_t)(nl - c->rbuf) + 1;

  for (int i = 0; i < count; i++) {
    if (pos >= c->rlen) return 0;
    if (c->rbuf[pos] != '$') return -1;
    nl = memchr(c->rbuf + pos, '\n', c->rlen - pos);
    if (!nl) return 0;
    int blen = atoi(c->rbuf + pos + 1);
    if (blen < 0) return -1;
    size_t hdr_end = (size_t)(nl - c->rbuf) + 1;
    if (hdr_end + (size_t)blen + 2 > c->rlen) return 0;
    char *arg = malloc((size_t)blen + 1);
    if (!arg) return -1;
    memcpy(arg, c->rbuf + hdr_end, (size_t)blen);
    arg[blen] = '\0';
    args[i] = arg;
    pos = hdr_end + (size_t)blen + 2;
  }

  *nargs = count;
  c->rlen -= pos;
  if (c->rlen > 0) memmove(c->rbuf, c->rbuf + pos, c->rlen);
  return 1;
}

/* Permission checking */

/* Check if a command name matches a single permit pattern.
 * Supports: "*" matches everything, "foo.*" matches "foo.anything",
 * exact match otherwise. */
static bool permit_matches(const char *pattern, const char *cmd) {
  size_t plen = strlen(pattern);
  if (plen == 1 && pattern[0] == '*')
    return true;
  if (plen >= 2 && pattern[plen - 1] == '*') {
    return strncasecmp(pattern, cmd, plen - 1) == 0;
  }
  return strcasecmp(pattern, cmd) == 0;
}

/* Check if client has permission for a command. Uses live config: api:<username> and api:* permit keys. */
static bool user_has_permit(api_client_t *c, const char *cmd) {
  char section[128];
  const char *uname = (c->username && c->username[0]) ? c->username : "*";
  snprintf(section, sizeof(section), "api:%s", uname);
  resp_object *sec = resp_map_get(global_cfg, section);
  if (sec && sec->type == RESPT_ARRAY) {
    for (size_t i = 0; i < sec->u.arr.n; i += 2) {
      if (i + 1 < sec->u.arr.n) {
        resp_object *key = &sec->u.arr.elem[i];
        resp_object *val = &sec->u.arr.elem[i + 1];
        if (key->type == RESPT_BULK && key->u.s && strcmp(key->u.s, "permit") == 0) {
          if (val->type == RESPT_ARRAY) {
            for (size_t j = 0; j < val->u.arr.n; j++) {
              resp_object *p = &val->u.arr.elem[j];
              if (p->type == RESPT_BULK && p->u.s && permit_matches(p->u.s, cmd))
                return true;
            }
          }
        }
      }
    }
  }
  if (strcmp(uname, "*") != 0) {
    resp_object *anon = resp_map_get(global_cfg, "api:*");
    if (anon && anon->type == RESPT_ARRAY) {
      for (size_t i = 0; i < anon->u.arr.n; i += 2) {
        resp_object *key = &anon->u.arr.elem[i];
        resp_object *val = &anon->u.arr.elem[i + 1];
        if (key->type == RESPT_BULK && key->u.s && strcmp(key->u.s, "permit") == 0) {
          if (val->type == RESPT_ARRAY) {
            for (size_t j = 0; j < val->u.arr.n; j++) {
              resp_object *p = &val->u.arr.elem[j];
              if (p->type == RESPT_BULK && p->u.s && permit_matches(p->u.s, cmd))
                return true;
            }
          }
        }
      }
    }
  }
  return false;
}

/* Hashmap callbacks */

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

/* Public: register a command */

void api_register_cmd(const char *name, char (*func)(api_client_t *, char **, int)) {
  if (!cmd_map)
    cmd_map = hashmap_new(sizeof(api_cmd_entry), 0, 0, 0, cmd_hash, cmd_compare, NULL, NULL);
  hashmap_set(cmd_map, &(api_cmd_entry){ .name = name, .func = func });
  log_trace("api: registered command '%s'", name);
}

static char cmdAUTH(api_client_t *c, char **args, int nargs) {
  if (nargs != 3) {
    api_write_err(c, "wrong number of arguments for 'auth' command (AUTH username password)");
    return 1;
  }
  const char *uname = args[1];
  const char *pass  = args[2];
  char section[128];
  snprintf(section, sizeof(section), "api:%s", uname);
  resp_object *sec = resp_map_get(global_cfg, section);
  const char *secret = sec ? resp_map_get_string(sec, "secret") : NULL;
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
  if (nargs == 1)
    return api_write_cstr(c, "+PONG\r\n") ? 1 : 0;
  if (nargs == 2)
    return api_write_bulk_cstr(c, args[1]) ? 1 : 0;
  return api_write_err(c, "wrong number of arguments for 'ping' command") ? 1 : 0;
}

static char cmdQUIT(api_client_t *c, char **args, int nargs) {
  (void)args; (void)nargs;
  api_write_ok(c);
  return 0;
}

static char cmdCOMMAND(api_client_t *c, char **args, int nargs) {
  (void)args; (void)nargs;
  if (!cmd_map)
    return api_write_array(c, 0) ? 1 : 0;

  size_t count = 0;
  size_t iter = 0;
  void *item;
  while (hashmap_iter(cmd_map, &iter, &item)) {
    const api_cmd_entry *e = item;
    if (user_has_permit(c, e->name))
      count++;
  }

  if (!api_write_array(c, count)) return 0;

  iter = 0;
  while (hashmap_iter(cmd_map, &iter, &item)) {
    const api_cmd_entry *e = item;
    if (user_has_permit(c, e->name)) {
      if (!api_write_bulk_cstr(c, e->name)) return 0;
    }
  }
  return 1;
}

/* Command dispatch */

static void init_builtins(void) {
  api_register_cmd("auth",    cmdAUTH);
  api_register_cmd("ping",    cmdPING);
  api_register_cmd("quit",    cmdQUIT);
  api_register_cmd("command", cmdCOMMAND);
}

/* Check if a command is a built-in that bypasses auth/permit checks */
static bool is_builtin(const char *name) {
  return (strcasecmp(name, "auth") == 0 ||
          strcasecmp(name, "ping") == 0 ||
          strcasecmp(name, "quit") == 0 ||
          strcasecmp(name, "command") == 0);
}

static void dispatch_command(api_client_t *c, char **args, int nargs) {
  if (nargs <= 0) return;

  for (char *p = args[0]; *p; p++) *p = (char)tolower((unsigned char)*p);

  const api_cmd_entry *cmd = hashmap_get(cmd_map, &(api_cmd_entry){ .name = args[0] });
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

/* TCP listener */

static int *create_listen_socket(const char *listen_addr) {
  const char *default_port = "6379";
  resp_object *api_sec = resp_map_get(global_cfg, "api");
  if (api_sec) {
    const char *cfg_port = resp_map_get_string(api_sec, "port");
    if (cfg_port && cfg_port[0]) default_port = cfg_port;
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
  socklen_t addrlen = sizeof(addr);
  int fd = accept(ready_fd, (struct sockaddr *)&addr, &addrlen);
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

  schedmod_pt_create(api_client_pt, state);
  log_trace("api: accepted connection, spawned client pt");
}

PT_THREAD(api_server_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  time_t loop_timestamp = 0;
  PT_BEGIN(pt);

  resp_object *api_sec = resp_map_get(global_cfg, "api");
  const char *listen_str = api_sec ? resp_map_get_string(api_sec, "listen") : NULL;
  if (!listen_str || !listen_str[0]) {
    log_info("api: no listen address configured, API server disabled");
    PT_EXIT(pt);
  }

  current_listen = strdup(listen_str);
  if (!current_listen) {
    PT_EXIT(pt);
  }

  init_builtins();
  int *fds = create_listen_socket(current_listen);
  if (!fds) {
    free(current_listen);
    current_listen = NULL;
    PT_EXIT(pt);
  }

  for (;;) {
    loop_timestamp = (time_t)(timestamp / 1000);

    if (loop_timestamp >= next_listen_check) {
      next_listen_check = loop_timestamp + 60;
      resp_object *api_sec = resp_map_get(global_cfg, "api");
      const char *new_str = api_sec ? resp_map_get_string(api_sec, "listen") : "";
      int rebind = (current_listen && (!new_str[0] || strcmp(current_listen, new_str) != 0)) ||
                   (!current_listen && new_str[0]);
      if (rebind) {
        if (fds) {
          for (int i = 1; i <= fds[0]; i++) {
            close(fds[i]);
          }
        }
        free(current_listen);
        current_listen = (new_str[0]) ? strdup(new_str) : NULL;
        if (current_listen) {
          int *new_fds = create_listen_socket(current_listen);
          if (new_fds) {
            fds = realloc(fds, sizeof(int) * (new_fds[0] + 1));
            fds[0] = new_fds[0];
            for (int i = 1; i <= new_fds[0]; i++) {
              fds[i] = new_fds[i];
            }
            free(new_fds);
          } else {
            free(current_listen);
            current_listen = NULL;
          }
        }
      }
    }

    if (fds && fds[0] > 0) {
      int *ready_fds = NULL;
      PT_WAIT_UNTIL(pt, schedmod_has_data(fds, &ready_fds) > 0);
      if (ready_fds && ready_fds[0] > 0) {
        for (int i = 1; i <= ready_fds[0]; i++) {
          handle_accept(ready_fds[i]);
        }
      }
      free(ready_fds);
    } else {
      PT_YIELD(pt);
    }
  }
  if (fds) {
    for (int i = 1; i <= fds[0]; i++) {
      close(fds[i]);
    }
    free(fds);
  }
  free(current_listen);
  current_listen = NULL;
  if (cmd_map) {
    hashmap_free(cmd_map);
    cmd_map = NULL;
  }

  PT_END(pt);
}

PT_THREAD(api_client_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  (void)timestamp;
  api_client_t *state = task->udata;

  PT_BEGIN(pt);

  state->fds = malloc(sizeof(int) * 2);
  if (!state->fds) {
    free(state);
    PT_EXIT(pt);
  }
  state->fds[0] = 1;
  state->fds[1] = state->fd;

  for (;;) {
    int *ready_fds = NULL;
    PT_WAIT_UNTIL(pt, schedmod_has_data(state->fds, &ready_fds) > 0);

    int ready_fd = -1;
    if (ready_fds && ready_fds[0] > 0) {
      for (int i = 1; i <= ready_fds[0]; i++) {
        if (ready_fds[i] == state->fd) {
          ready_fd = state->fd;
          break;
        }
      }
    }
    free(ready_fds);

    if (ready_fd != state->fd) continue;

    size_t space = sizeof(state->rbuf) - state->rlen;
    if (space == 0) {
      break;
    }
    ssize_t n = recv(state->fd, state->rbuf + state->rlen, space, 0);
    if (n <= 0) {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
        break;
    }
    state->rlen += (size_t)n;

    char *args[MAX_ARGS];
    int nargs;
    int rc = 0;
    while (state->fd >= 0 && (rc = parse_resp_command(state, args, MAX_ARGS, &nargs)) > 0) {
      dispatch_command(state, args, nargs);
      for (int j = 0; j < nargs; j++) free(args[j]);
    }
    if (rc < 0) {
      api_write_err(state, "Protocol error");
    }

    client_flush(state);

    if (state->fd < 0) break;
  }

  if (state->fd >= 0) {
    close(state->fd);
  }
  free(state->fds);
  free(state->wbuf);
  free(state->username);
  free(state);

  PT_END(pt);
}
