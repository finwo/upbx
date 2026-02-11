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
#include "common/pt.h"
#include "common/socket_util.h"
#include "config.h"
#include "AppModule/service/api.h"

/* Constants */

#define API_MAX_CLIENTS   8
#define READ_BUF_SIZE     4096
#define WRITE_BUF_INIT    4096
#define MAX_ARGS          32

/* Per-client connection state */

struct api_client {
  int       fd;
  config_api_user *user;   /* authenticated user (NULL = anonymous/[api:*]) */
  char      rbuf[READ_BUF_SIZE];
  size_t    rlen;           /* bytes in read buffer */
  char     *wbuf;
  size_t    wlen;
  size_t    wcap;
};

/* Command entry */

typedef struct {
  const char  *name;
  api_cmd_func func;
} api_cmd_entry;

/* Module state */

static int              listen_fd = -1;
static struct api_client clients[API_MAX_CLIENTS];
static struct hashmap  *cmd_map = NULL;
static config_api_user *anon_user = NULL;  /* [api:*] user, may be NULL */

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

bool api_write_bulk_time(api_client_t *c, long t) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%ld", t);
  return api_write_bulk_cstr(c, buf);
}

bool api_write_kv(api_client_t *c, const char *key, const char *val) {
  if (!api_write_bulk_cstr(c, key)) return false;
  return api_write_bulk_cstr(c, val ? val : "");
}

bool api_write_kv_int(api_client_t *c, const char *key, int val) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%d", val);
  if (!api_write_bulk_cstr(c, key)) return false;
  return api_write_bulk_cstr(c, buf);
}

bool api_write_kv_time(api_client_t *c, const char *key, long t) {
  char buf[32];
  snprintf(buf, sizeof(buf), "%ld", t);
  if (!api_write_bulk_cstr(c, key)) return false;
  return api_write_bulk_cstr(c, buf);
}

/* Client lifecycle */

static void client_init(struct api_client *c) {
  memset(c, 0, sizeof(*c));
  c->fd = -1;
}

static void client_close(struct api_client *c) {
  if (c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
  }
  free(c->wbuf);
  c->wbuf = NULL;
  c->wlen = c->wcap = 0;
  c->rlen = 0;
  c->user = NULL;
}

static void client_flush(struct api_client *c) {
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

static int parse_resp_command(struct api_client *c, char **args, int max_args, int *nargs) {
  *nargs = 0;
  if (c->rlen == 0) return 0;

  /* Inline command: line not starting with '*' */
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

  /* Multibulk: *<count>\r\n followed by $<len>\r\n<data>\r\n ... */
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
    /* Prefix match: "metrics.*" matches "metrics.keys" etc. */
    return strncasecmp(pattern, cmd, plen - 1) == 0;
  }
  return strcasecmp(pattern, cmd) == 0;
}

/* Check if a user has permission for a command.
 * Checks user's own permits + anonymous user's permits (effective permissions). */
static bool user_has_permit(config_api_user *user, const char *cmd) {
  /* Check user's own permits */
  if (user) {
    for (size_t i = 0; i < user->permit_count; i++) {
      if (permit_matches(user->permits[i], cmd))
        return true;
    }
  }
  /* Check anonymous user's permits (inherited by all) */
  if (anon_user && anon_user != user) {
    for (size_t i = 0; i < anon_user->permit_count; i++) {
      if (permit_matches(anon_user->permits[i], cmd))
        return true;
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

void api_register_cmd(const char *name, api_cmd_func func) {
  if (!cmd_map)
    cmd_map = hashmap_new(sizeof(api_cmd_entry), 0, 0, 0, cmd_hash, cmd_compare, NULL, NULL);
  hashmap_set(cmd_map, &(api_cmd_entry){ .name = name, .func = func });
  log_trace("api: registered command '%s'", name);
}

/* Built-in command handlers */

static bool cmdAUTH(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  if (nargs != 3) {
    return api_write_err(c, "wrong number of arguments for 'auth' command (AUTH username password)");
  }
  const char *uname = args[1];
  const char *pass  = args[2];

  /* Find matching user (not anonymous) */
  for (size_t i = 0; i < cfg->api.user_count; i++) {
    config_api_user *u = &cfg->api.users[i];
    if (strcmp(u->username, "*") == 0) continue; /* skip anonymous */
    if (strcmp(u->username, uname) == 0) {
      if (u->secret && strcmp(u->secret, pass) == 0) {
        c->user = u;
        log_debug("api: client authenticated as '%s'", uname);
        return api_write_ok(c);
      }
      return api_write_err(c, "invalid credentials");
    }
  }
  return api_write_err(c, "invalid credentials");
}

static bool cmdPING(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  (void)cfg;
  if (nargs == 1)
    return api_write_cstr(c, "+PONG\r\n");
  if (nargs == 2)
    return api_write_bulk_cstr(c, args[1]);
  return api_write_err(c, "wrong number of arguments for 'ping' command");
}

static bool cmdQUIT(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  (void)cfg; (void)args; (void)nargs;
  api_write_ok(c);
  return false; /* signal close */
}

static bool cmdCOMMAND(api_client_t *c, struct upbx_config *cfg, char **args, int nargs) {
  (void)cfg; (void)args; (void)nargs;
  if (!cmd_map)
    return api_write_array(c, 0);

  /* Count commands the client has access to */
  size_t count = 0;
  size_t iter = 0;
  void *item;
  while (hashmap_iter(cmd_map, &iter, &item)) {
    const api_cmd_entry *e = item;
    if (user_has_permit(c->user, e->name))
      count++;
  }

  /* Always include the built-ins */
  /* (auth, quit, command are always allowed but may not be in the permit list) */
  /* We list all commands the user can use */
  if (!api_write_array(c, count)) return false;

  iter = 0;
  while (hashmap_iter(cmd_map, &iter, &item)) {
    const api_cmd_entry *e = item;
    if (user_has_permit(c->user, e->name)) {
      if (!api_write_bulk_cstr(c, e->name)) return false;
    }
  }
  return true;
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

static void dispatch_command(struct api_client *c, struct upbx_config *cfg, char **args, int nargs) {
  if (nargs <= 0) return;

  /* Lowercase the command name */
  for (char *p = args[0]; *p; p++) *p = (char)tolower((unsigned char)*p);

  const api_cmd_entry *cmd = hashmap_get(cmd_map, &(api_cmd_entry){ .name = args[0] });
  if (!cmd) {
    api_write_err(c, "unknown command");
    return;
  }

  /* Built-ins (auth, quit, command) are always allowed */
  if (!is_builtin(args[0])) {
    /* Check permission */
    if (!user_has_permit(c->user, args[0])) {
      api_write_err(c, "no permission");
      return;
    }
  }

  if (!cmd->func(c, cfg, args, nargs)) {
    /* handler returned false = close connection */
    client_flush(c);
    client_close(c);
  }
}

/* TCP listener */

static int create_listen_socket(const char *listen_addr) {
  char host[256] = "127.0.0.1";
  char port[32] = "6379";
  const char *colon = strrchr(listen_addr, ':');
  if (colon) {
    size_t hlen = (size_t)(colon - listen_addr);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, listen_addr, hlen);
    host[hlen] = '\0';
    snprintf(port, sizeof(port), "%s", colon + 1);
  } else {
    snprintf(port, sizeof(port), "%s", listen_addr);
  }

  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
    log_error("api: getaddrinfo failed for %s", listen_addr);
    return -1;
  }

  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) {
    log_error("api: socket() failed: %s", strerror(errno));
    freeaddrinfo(res);
    return -1;
  }

  int opt = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
    log_error("api: bind(%s) failed: %s", listen_addr, strerror(errno));
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  freeaddrinfo(res);

  if (listen(fd, 8) < 0) {
    log_error("api: listen() failed: %s", strerror(errno));
    close(fd);
    return -1;
  }

  set_socket_nonblocking(fd, 1);
  log_info("api: listening on %s", listen_addr);
  return fd;
}

/* Connection management */

static void accept_connection(void) {
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);
  int fd = accept(listen_fd, (struct sockaddr *)&addr, &addrlen);
  if (fd < 0) return;
  set_socket_nonblocking(fd, 1);
  int slot = -1;
  for (int i = 0; i < API_MAX_CLIENTS; i++) {
    if (clients[i].fd < 0) { slot = i; break; }
  }
  if (slot < 0) {
    const char *msg = "-ERR max connections\r\n";
    send(fd, msg, strlen(msg), 0);
    close(fd);
    log_debug("api: rejected connection, max clients reached");
  } else {
    client_init(&clients[slot]);
    clients[slot].fd = fd;
    /* Anonymous user starts with [api:*] permissions */
    clients[slot].user = anon_user;
    log_trace("api: accepted connection (slot %d)", slot);
  }
}

static void process_client(struct api_client *c, fd_set *read_set, struct upbx_config *cfg) {
  if (c->fd < 0) return;

  if (!FD_ISSET(c->fd, read_set)) {
    client_flush(c);
    return;
  }

  size_t space = sizeof(c->rbuf) - c->rlen;
  if (space == 0) {
    client_close(c);
    return;
  }
  ssize_t n = recv(c->fd, c->rbuf + c->rlen, space, 0);
  if (n <= 0) {
    if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
      client_close(c);
    return;
  }
  c->rlen += (size_t)n;

  char *args[MAX_ARGS];
  int nargs;
  int rc;
  while (c->fd >= 0 && (rc = parse_resp_command(c, args, MAX_ARGS, &nargs)) > 0) {
    dispatch_command(c, cfg, args, nargs);
    for (int j = 0; j < nargs; j++) free(args[j]);
  }
  if (rc < 0) {
    api_write_err(c, "Protocol error");
    client_flush(c);
    client_close(c);
    return;
  }
  client_flush(c);
}

/* Public API */

void api_start(struct upbx_config *cfg) {
  for (int i = 0; i < API_MAX_CLIENTS; i++)
    client_init(&clients[i]);

  if (!cfg->api.listen || !cfg->api.listen[0]) {
    log_debug("api: no listen address configured, API server disabled");
    return;
  }

  /* Find anonymous user [api:*] */
  anon_user = NULL;
  for (size_t i = 0; i < cfg->api.user_count; i++) {
    if (strcmp(cfg->api.users[i].username, "*") == 0) {
      anon_user = &cfg->api.users[i];
      break;
    }
  }

  init_builtins();
  listen_fd = create_listen_socket(cfg->api.listen);
}

void api_fill_fds(fd_set *read_set, int *maxfd) {
  if (listen_fd < 0) return;
  FD_SET(listen_fd, read_set);
  if (listen_fd > *maxfd) *maxfd = listen_fd;
  for (int i = 0; i < API_MAX_CLIENTS; i++) {
    if (clients[i].fd >= 0) {
      FD_SET(clients[i].fd, read_set);
      if (clients[i].fd > *maxfd) *maxfd = clients[i].fd;
    }
  }
}

PT_THREAD(api_pt(struct pt *pt, fd_set *read_set, struct upbx_config *cfg)) {
  PT_BEGIN(pt);
  for (;;) {
    if (listen_fd >= 0) {
      if (FD_ISSET(listen_fd, read_set))
        accept_connection();
      for (int i = 0; i < API_MAX_CLIENTS; i++)
        process_client(&clients[i], read_set, cfg);
    }
    PT_YIELD(pt);
  }
  PT_END(pt);
}

void api_stop(void) {
  for (int i = 0; i < API_MAX_CLIENTS; i++) {
    if (clients[i].fd >= 0) client_close(&clients[i]);
  }
  if (listen_fd >= 0) {
    close(listen_fd);
    listen_fd = -1;
  }
  if (cmd_map) {
    hashmap_free(cmd_map);
    cmd_map = NULL;
  }
  anon_user = NULL;
}
