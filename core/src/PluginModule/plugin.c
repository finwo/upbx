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
#include <time.h>
#include <sys/wait.h>

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

/* Given a RESP array interpreted as a map (even-length: key, value, key, value, ...), return a pointer
 * to the value element for the given key, or NULL. Key comparison uses string value of BULK/SIMPLE elements.
 * Returned pointer is into the array; valid until the response object is freed. */
plugmod_resp_object *plugmod_resp_map_get(const plugmod_resp_object *o, const char *key) {
  if (!o || !key || o->type != PLUGMOD_RESPT_ARRAY) return NULL;
  size_t n = o->u.arr.n;
  if (n & 1) return NULL; /* odd length is not a valid map */
  for (size_t i = 0; i < n; i += 2) {
    const plugmod_resp_object *k = &o->u.arr.elem[i];
    const char *s = (k->type == PLUGMOD_RESPT_BULK || k->type == PLUGMOD_RESPT_SIMPLE) ? k->u.s : NULL;
    if (s && strcmp(s, key) == 0 && i + 1 < n)
      return (plugmod_resp_object *)&o->u.arr.elem[i + 1];
  }
  return NULL;
}

/* Given a map and key, return the value's string (BULK/SIMPLE) or NULL. Does not allocate; valid until map freed. */
const char *plugmod_resp_map_get_string(const plugmod_resp_object *o, const char *key) {
  plugmod_resp_object *val = plugmod_resp_map_get(o, key);
  if (!val) return NULL;
  if (val->type == PLUGMOD_RESPT_BULK || val->type == PLUGMOD_RESPT_SIMPLE)
    return val->u.s;
  return NULL;
}

/* Append one RESP-encoded object to buf; realloc as needed. *buf may change. Returns 0 on success. */
static int resp_append_object(char **buf, size_t *cap, size_t *len, const plugmod_resp_object *o) {
  if (!o) return -1;
  size_t need = *len + 256;
  if (o->type == PLUGMOD_RESPT_BULK || o->type == PLUGMOD_RESPT_SIMPLE || o->type == PLUGMOD_RESPT_ERROR) {
    size_t slen = o->u.s ? strlen(o->u.s) : 0;
    need = *len + 32 + slen + 2;
  } else if (o->type == PLUGMOD_RESPT_ARRAY) {
    need = *len + 32;
    for (size_t i = 0; i < o->u.arr.n; i++)
      need += 64; /* rough; will grow in recurse */
  }
  if (need > *cap) {
    size_t newcap = need + 4096;
    char *n = realloc(*buf, newcap);
    if (!n) return -1;
    *buf = n;
    *cap = newcap;
  }
  switch (o->type) {
    case PLUGMOD_RESPT_SIMPLE: {
      const char *s = o->u.s ? o->u.s : "";
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "+%s\r\n", s);
      break;
    }
    case PLUGMOD_RESPT_ERROR: {
      const char *s = o->u.s ? o->u.s : "";
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "-%s\r\n", s);
      break;
    }
    case PLUGMOD_RESPT_INT:
      *len += (size_t)snprintf(*buf + *len, *cap - *len, ":%lld\r\n", (long long)o->u.i);
      break;
    case PLUGMOD_RESPT_BULK: {
      const char *s = o->u.s ? o->u.s : "";
      size_t slen = strlen(s);
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "$%zu\r\n%s\r\n", slen, s);
      break;
    }
    case PLUGMOD_RESPT_ARRAY: {
      size_t n = o->u.arr.n;
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "*%zu\r\n", n);
      for (size_t i = 0; i < n; i++) {
        if (resp_append_object(buf, cap, len, &o->u.arr.elem[i]) != 0)
          return -1;
      }
      break;
    }
    default:
      return -1;
  }
  return 0;
}

static int resp_encode_array_objects(int argc, const plugmod_resp_object *const *argv, char **out_buf, size_t *out_len) {
  size_t cap = 64;
  size_t len = 0;
  char *buf = malloc(cap);
  if (!buf) return -1;
  len += (size_t)snprintf(buf + len, cap - len, "*%d\r\n", argc);
  if (len >= cap) { free(buf); return -1; }
  for (int i = 0; i < argc; i++) {
    if (resp_append_object(&buf, &cap, &len, argv[i]) != 0) {
      free(buf);
      return -1;
    }
  }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

static int resp_encode_request(const char *method, int argc, const plugmod_resp_object *const *argv,
  char **out_buf, size_t *out_len) {
  plugmod_resp_object method_obj = { .type = PLUGMOD_RESPT_BULK, .u = { .s = (char *)method } };
  size_t cap = 128;
  size_t len = 0;
  char *buf = malloc(cap);
  if (!buf) return -1;
  len += (size_t)snprintf(buf + len, cap - len, "*%d\r\n", argc + 1);
  if (len >= cap) { free(buf); return -1; }
  if (resp_append_object(&buf, &cap, &len, &method_obj) != 0) {
    free(buf);
    return -1;
  }
  for (int i = 0; i < argc; i++) {
    if (resp_append_object(&buf, &cap, &len, argv[i]) != 0) {
      free(buf);
      return -1;
    }
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
  int stopping;
  time_t stop_sent_at;
  unsigned long long config_hash;
  char *exec;
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
  free(p->exec);
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
  out->stopping = 0;
  out->stop_sent_at = 0;
  out->config_hash = 0;
  out->exec = strdup(exec_path);
  if (set_socket_nonblocking(out->fd_read, 0) != 0 || set_socket_nonblocking(out->fd_write, 0) != 0) {
    plugin_state_free(out);
    return -1;
  }
  return 0;
}

static int do_discovery(plugin_state_t *p) {
  if (!discovery_cmd_used) return 0;
  plugmod_resp_object disc_obj = { .type = PLUGMOD_RESPT_BULK, .u = { .s = (char *)discovery_cmd_used } };
  const plugmod_resp_object *av[] = { &disc_obj };
  char *req = NULL;
  size_t req_len;
  if (resp_encode_array_objects(1, av, &req, &req_len) != 0) return -1;
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
    p->config_hash = configs[i].config_hash;
    if (discovery_cmd_used && do_discovery(p) != 0) {
      log_error("plugin %s: discovery failed", p->name);
      plugin_state_free(p);
      continue;
    }
    log_debug("plugin %s: %zu methods, %zu events", p->name, p->method_count, p->event_count);
    plugin_n++;
  }
}

void plugmod_stop_plugin(const char *name) {
  plugin_state_t *p = find_plugin(name);
  if (!p || p->stopping || p->pid <= 0) return;
  kill(p->pid, SIGINT);
  p->stopping = 1;
  p->stop_sent_at = time(NULL);
}

static void remove_plugin_at(size_t i) {
  plugin_state_free(&plugins[i]);
  if (i < plugin_n - 1)
    memmove(&plugins[i], &plugins[i + 1], (plugin_n - 1 - i) * sizeof(plugin_state_t));
  plugin_n--;
}

void plugmod_tick(void) {
  time_t now = time(NULL);
  for (size_t i = plugin_n; i > 0; i--) {
    size_t idx = i - 1;
    plugin_state_t *p = &plugins[idx];
    if (!p->stopping || p->pid <= 0) continue;
    if (now - p->stop_sent_at < 30) continue;
    kill(p->pid, SIGKILL);
    int status;
    waitpid(p->pid, &status, 0);
    remove_plugin_at(idx);
  }
}

int plugmod_start_plugin(const char *name, const char *exec, unsigned long long config_hash) {
  if (!name || !exec || !exec[0]) return -1;
  if (find_plugin(name) != NULL) return -1; /* already running or stopping */
  if (!discovery_cmd_used) return -1;
  if (plugin_n >= plugin_cap) {
    size_t newcap = plugin_cap ? plugin_cap * 2 : 4;
    plugin_state_t *new_p = realloc(plugins, newcap * sizeof(plugin_state_t));
    if (!new_p) return -1;
    plugins = new_p;
    plugin_cap = newcap;
  }
  plugin_state_t *p = &plugins[plugin_n];
  memset(p, 0, sizeof(*p));
  p->fd_read = p->fd_write = -1;
  if (spawn_plugin(name, exec, p) != 0) return -1;
  p->config_hash = config_hash;
  if (do_discovery(p) != 0) {
    log_error("plugin %s: discovery failed", p->name);
    plugin_state_free(p);
    return -1;
  }
  log_debug("plugin %s: %zu methods, %zu events", p->name, p->method_count, p->event_count);
  plugin_n++;
  return 0;
}

void plugmod_sync(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd, const char **event_prefixes, size_t n_event_prefixes) {
  plugmod_tick();
  discovery_cmd_used = discovery_cmd;
  event_prefixes_used = event_prefixes;
  event_prefixes_n = n_event_prefixes;
  for (size_t i = 0; i < plugin_n; i++) {
    plugin_state_t *p = &plugins[i];
    if (p->stopping) continue;
    const plugmod_config_item *c = NULL;
    for (size_t j = 0; j < n; j++)
      if (configs[j].name && strcmp(p->name, configs[j].name) == 0) { c = &configs[j]; break; }
    if (!c) {
      plugmod_stop_plugin(p->name);
      continue;
    }
    if (c->exec && p->exec && strcmp(c->exec, p->exec) != 0) {
      plugmod_stop_plugin(p->name);
      continue;
    }
    if (c->config_hash != 0 && p->config_hash != c->config_hash) {
      plugmod_stop_plugin(p->name);
      continue;
    }
  }
  for (size_t j = 0; j < n; j++) {
    if (!configs[j].exec || !configs[j].exec[0]) continue;
    if (find_plugin(configs[j].name) != NULL) continue;
    plugmod_start_plugin(configs[j].name, configs[j].exec, configs[j].config_hash);
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

int plugmod_invoke_response(const char *plugin_name, const char *method, int argc, const plugmod_resp_object *const *argv,
  plugmod_resp_object **out) {
  plugin_state_t *p = find_plugin(plugin_name);
  if (!p || p->stopping || !out) return -1;
  *out = NULL;
  char *buf = NULL;
  size_t len = 0;
  if (resp_encode_request(method, argc, argv, &buf, &len) != 0) return -1;
  if (write(p->fd_write, buf, len) != (ssize_t)len) {
    free(buf);
    return -1;
  }
  free(buf);
  *out = resp_read(p->fd_read);
  return (*out) ? 0 : -1;
}

int plugmod_invoke(const char *plugin_name, const char *method, int argc, const plugmod_resp_object *const *argv) {
  log_debug("plugin call: %s -> %s (%d args)", plugin_name, method, argc);
  plugmod_resp_object *r = NULL;
  int ret = plugmod_invoke_response(plugin_name, method, argc, argv, &r);
  if (r) plugmod_resp_free(r);
  return ret;
}

int plugmod_has_event(const char *plugin_name, const char *event_name) {
  plugin_state_t *p = find_plugin(plugin_name);
  if (!p || p->stopping) return 0;
  for (size_t i = 0; i < p->event_count; i++)
    if (strcmp(p->events[i], event_name) == 0)
      return 1;
  return 0;
}

void plugmod_notify_event(const char *event_name, int argc, const plugmod_resp_object *const *argv) {
  log_debug("plugin event %s (%d args)", event_name, argc);
  for (size_t i = 0; i < plugin_n; i++) {
    if (plugins[i].stopping) continue;
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
