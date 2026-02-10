/*
 * Generic plugin module: RESP over stdio, spawn, discovery, invoke.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>

#include "common/socket_util.h"
#include "rxi/log.h"
#include "PluginModule/plugin.h"

#define MAX_BULK_LEN    (256 * 1024)
#define LINE_BUF        4096

static void resp_free_internal(plugmod_resp_object *o);

static int resp_read_byte(int fd) {
  unsigned char c;
  if (read(fd, &c, 1) != 1)
    return -1;
  return (int)c;
}

static int resp_read_line(int fd, char *buf, size_t buf_size) {
  size_t i = 0;
  int prev = -1;
  while (i + 1 < buf_size) {
    int b = resp_read_byte(fd);
    if (b < 0) return -1;
    if (prev == '\r' && b == '\n') {
      buf[i - 1] = '\0';
      return 0;
    }
    prev = b;
    buf[i++] = (char)b;
  }
  return -1;
}

static plugmod_resp_object *resp_read(int fd) {
  int type_c = resp_read_byte(fd);
  if (type_c < 0) return NULL;
  plugmod_resp_object *o = calloc(1, sizeof(plugmod_resp_object));
  if (!o) return NULL;
  char line[LINE_BUF];
  switch ((char)type_c) {
    case '+':
      o->type = PLUGMOD_RESPT_SIMPLE;
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      o->u.s = strdup(line);
      break;
    case '-':
      o->type = PLUGMOD_RESPT_ERROR;
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      o->u.s = strdup(line);
      break;
    case ':': {
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      o->type = PLUGMOD_RESPT_INT;
      o->u.i = (long long)strtoll(line, NULL, 10);
      break;
    }
    case '$': {
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      long len = strtol(line, NULL, 10);
      if (len < 0 || len > (long)MAX_BULK_LEN) { free(o); return NULL; }
      o->type = PLUGMOD_RESPT_BULK;
      if (len == 0) {
        o->u.s = strdup("");
        if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o->u.s); free(o); return NULL; }
      } else {
        o->u.s = malloc((size_t)len + 1);
        if (!o->u.s) { free(o); return NULL; }
        if (read(fd, o->u.s, (size_t)len) != (ssize_t)len) { free(o->u.s); free(o); return NULL; }
        o->u.s[len] = '\0';
        if (resp_read_byte(fd) != '\r' || resp_read_byte(fd) != '\n') { free(o->u.s); free(o); return NULL; }
      }
      break;
    }
    case '*': {
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      long n = strtol(line, NULL, 10);
      if (n < 0 || n > 65536) { free(o); return NULL; }
      o->type = PLUGMOD_RESPT_ARRAY;
      o->u.arr.n = (size_t)n;
      o->u.arr.elem = n ? calloc((size_t)n, sizeof(plugmod_resp_object)) : NULL;
      if (n && !o->u.arr.elem) { free(o); return NULL; }
      for (size_t i = 0; i < (size_t)n; i++) {
        plugmod_resp_object *sub = resp_read(fd);
        if (!sub) {
          for (size_t j = 0; j < i; j++) resp_free_internal(&o->u.arr.elem[j]);
          free(o->u.arr.elem);
          free(o);
          return NULL;
        }
        o->u.arr.elem[i] = *sub;
        free(sub);
      }
      break;
    }
    default:
      free(o);
      return NULL;
  }
  return o;
}

static void resp_free_internal(plugmod_resp_object *o) {
  if (!o) return;
  if (o->type == PLUGMOD_RESPT_SIMPLE || o->type == PLUGMOD_RESPT_ERROR || o->type == PLUGMOD_RESPT_BULK) {
    free(o->u.s);
  } else if (o->type == PLUGMOD_RESPT_ARRAY) {
    for (size_t i = 0; i < o->u.arr.n; i++)
      resp_free_internal(&o->u.arr.elem[i]);
    free(o->u.arr.elem);
  }
}

void plugmod_resp_free(plugmod_resp_object *o) {
  resp_free_internal(o);
}

static int resp_encode_array(int argc, const char **argv, char **out_buf, size_t *out_len) {
  size_t cap = 64;
  size_t len = 0;
  char *buf = malloc(cap);
  if (!buf) return -1;
  len += (size_t)snprintf(buf + len, cap - len, "*%d\r\n", argc);
  if (len >= cap) { free(buf); return -1; }
  for (int i = 0; i < argc; i++) {
    size_t slen = strlen(argv[i]);
    size_t need = len + 32 + slen + 2;
    if (need > cap) {
      cap = need + 4096;
      char *n = realloc(buf, cap);
      if (!n) { free(buf); return -1; }
      buf = n;
    }
    len += (size_t)snprintf(buf + len, cap - len, "$%zu\r\n%s\r\n", slen, argv[i]);
  }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

typedef struct {
  char *name;
  pid_t pid;
  int fd_write;
  int fd_read;
  char **methods;
  size_t method_count;
  char **events;
  size_t event_count;
} plugin_state_t;

static plugin_state_t *plugins;
static size_t plugin_cap;
static size_t plugin_n;
static const char *discovery_cmd_used;
static const char **event_prefixes_used;
static size_t event_prefixes_n;

static void plugin_state_free(plugin_state_t *p) {
  if (!p) return;
  free(p->name);
  for (size_t i = 0; i < p->method_count; i++) free(p->methods[i]);
  free(p->methods);
  for (size_t i = 0; i < p->event_count; i++) free(p->events[i]);
  free(p->events);
  if (p->fd_read >= 0) close(p->fd_read);
  if (p->fd_write >= 0) close(p->fd_write);
}

static plugin_state_t *find_plugin(const char *name) {
  for (size_t i = 0; i < plugin_n; i++)
    if (strcmp(plugins[i].name, name) == 0)
      return &plugins[i];
  return NULL;
}

static int spawn_plugin(const char *name, const char *exec_path, plugin_state_t *out) {
  int stdin_pipe[2], stdout_pipe[2];
  if (pipe(stdin_pipe) != 0 || pipe(stdout_pipe) != 0) {
    log_error("plugin %s: pipe failed", name);
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(stdin_pipe[0]); close(stdin_pipe[1]);
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    log_error("plugin %s: fork failed", name);
    return -1;
  }
  if (pid == 0) {
    dup2(stdin_pipe[0], STDIN_FILENO);
    dup2(stdout_pipe[1], STDOUT_FILENO);
    close(stdin_pipe[0]); close(stdin_pipe[1]);
    close(stdout_pipe[0]); close(stdout_pipe[1]);
    execl("/bin/sh", "sh", "-c", exec_path, (char *)NULL);
    _exit(127);
  }
  close(stdin_pipe[0]);
  close(stdout_pipe[1]);
  out->name = strdup(name);
  out->pid = pid;
  out->fd_write = stdin_pipe[1];
  out->fd_read = stdout_pipe[0];
  out->methods = NULL;
  out->method_count = 0;
  out->events = NULL;
  out->event_count = 0;
  /* Use blocking I/O on plugin pipes so we don't need select(); plugins are local and expected to respond quickly. */
  if (set_socket_nonblocking(out->fd_read, 0) != 0 || set_socket_nonblocking(out->fd_write, 0) != 0) {
    plugin_state_free(out);
    return -1;
  }
  return 0;
}

static int do_discovery(plugin_state_t *p) {
  if (!discovery_cmd_used) return 0;
  const char *argv[1] = { discovery_cmd_used };
  char *req = NULL;
  size_t req_len;
  if (resp_encode_array(1, argv, &req, &req_len) != 0) return -1;
  ssize_t n = write(p->fd_write, req, req_len);
  free(req);
  if (n != (ssize_t)req_len) return -1;
  plugmod_resp_object *r = resp_read(p->fd_read);
  if (!r || r->type != PLUGMOD_RESPT_ARRAY) {
    if (r) plugmod_resp_free(r);
    return -1;
  }
  int is_event;
  for (size_t i = 0; i < r->u.arr.n; i++) {
    plugmod_resp_object *e = &r->u.arr.elem[i];
    const char *s = (e->type == PLUGMOD_RESPT_BULK || e->type == PLUGMOD_RESPT_SIMPLE) ? e->u.s : NULL;
    if (!s) continue;
    is_event = 0;
    for (size_t p = 0; p < event_prefixes_n && event_prefixes_used && event_prefixes_used[p]; p++) {
      size_t plen = strlen(event_prefixes_used[p]);
      if (plen && strncmp(s, event_prefixes_used[p], plen) == 0) { is_event = 1; break; }
    }
    if (is_event) {
      char **new_ev = realloc(p->events, (p->event_count + 1) * sizeof(char *));
      if (!new_ev) break;
      p->events = new_ev;
      p->events[p->event_count++] = strdup(s);
    } else {
      char **new_m = realloc(p->methods, (p->method_count + 1) * sizeof(char *));
      if (!new_m) break;
      p->methods = new_m;
      p->methods[p->method_count++] = strdup(s);
    }
  }
  plugmod_resp_free(r);
  return 0;
}

void plugmod_start(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd, const char **event_prefixes, size_t n_event_prefixes) {
  log_trace("plugmod_start: %zu plugin configs, discovery=%s", n, discovery_cmd ? discovery_cmd : "(none)");
  discovery_cmd_used = discovery_cmd;
  event_prefixes_used = event_prefixes;
  event_prefixes_n = n_event_prefixes;
  plugin_n = 0;
  for (size_t i = 0; i < n; i++) {
    if (!configs[i].exec || !configs[i].exec[0]) continue;
    if (plugin_n >= plugin_cap) {
      size_t newcap = plugin_cap ? plugin_cap * 2 : 4;
      plugin_state_t *new_p = realloc(plugins, newcap * sizeof(plugin_state_t));
      if (!new_p) break;
      plugins = new_p;
      plugin_cap = newcap;
    }
    plugin_state_t *p = &plugins[plugin_n];
    memset(p, 0, sizeof(*p));
    p->fd_read = p->fd_write = -1;
    if (spawn_plugin(configs[i].name, configs[i].exec, p) != 0)
      continue;
    if (discovery_cmd_used && do_discovery(p) != 0) {
      log_error("plugin %s: discovery failed", p->name);
      plugin_state_free(p);
      continue;
    }
    log_debug("plugin %s: %zu methods, %zu events", p->name, p->method_count, p->event_count);
    plugin_n++;
  }
}

void plugmod_stop(void) {
  for (size_t i = 0; i < plugin_n; i++) {
    if (plugins[i].pid > 0)
      kill(plugins[i].pid, SIGTERM);
    plugin_state_free(&plugins[i]);
  }
  plugin_n = 0;
  free(plugins);
  plugins = NULL;
  plugin_cap = 0;
}

int plugmod_invoke_response(const char *plugin_name, const char *method, int argc, const char **argv,
  plugmod_resp_object **out) {
  plugin_state_t *p = find_plugin(plugin_name);
  if (!p || !out) return -1;
  *out = NULL;
  char **all = malloc((size_t)(argc + 1) * sizeof(char *));
  if (!all) return -1;
  all[0] = (char *)method;
  for (int i = 0; i < argc; i++)
    all[i + 1] = (char *)argv[i];
  char *buf = NULL;
  size_t len = 0;
  int ret = resp_encode_array(argc + 1, (const char **)all, &buf, &len);
  free(all);
  if (ret != 0) return -1;
  if (write(p->fd_write, buf, len) != (ssize_t)len) {
    free(buf);
    return -1;
  }
  free(buf);
  *out = resp_read(p->fd_read);
  return (*out) ? 0 : -1;
}

int plugmod_invoke(const char *plugin_name, const char *method, int argc, const char **argv) {
  log_debug("plugin call: %s -> %s (%d args)", plugin_name, method, argc);
  plugmod_resp_object *r = NULL;
  int ret = plugmod_invoke_response(plugin_name, method, argc, argv, &r);
  if (r) plugmod_resp_free(r);
  return ret;
}

int plugmod_has_event(const char *plugin_name, const char *event_name) {
  plugin_state_t *p = find_plugin(plugin_name);
  if (!p) return 0;
  for (size_t i = 0; i < p->event_count; i++)
    if (strcmp(p->events[i], event_name) == 0)
      return 1;
  return 0;
}

void plugmod_notify_event(const char *event_name, int argc, const char **argv) {
  log_debug("plugin event %s (%d args)", event_name, argc);
  for (size_t i = 0; i < plugin_n; i++) {
    if (!plugmod_has_event(plugins[i].name, event_name)) continue;
    plugmod_invoke(plugins[i].name, event_name, argc, argv);
  }
}

size_t plugmod_count(void) {
  return plugin_n;
}

const char *plugmod_name_at(size_t i) {
  if (i >= plugin_n) return NULL;
  return plugins[i].name;
}
