/*
 * Generic plugin module: RESP over stdio, spawn, discovery, invoke.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
#include "RespModule/resp.h"

typedef struct {
  char *name;
  pid_t pid;
  int fd_write;
  int fd_read;
  char **methods;      /* single list of callable names (methods and events) */
  size_t method_count;
  int stopping;
  time_t stop_sent_at;
  unsigned long long config_hash;
  int restart_on_update;
  char *exec;
} plugin_state_t;

static plugin_state_t *plugins;
static size_t plugin_cap;
static size_t plugin_n;
static const char *discovery_cmd_used;
static plugmod_after_discovery_fn after_discovery_cb_used;
static void *after_discovery_user_used;

static void plugin_state_free(plugin_state_t *p) {
  if (!p) return;
  free(p->name);
  free(p->exec);
  for (size_t i = 0; i < p->method_count; i++) free(p->methods[i]);
  free(p->methods);
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
  out->stopping = 0;
  out->stop_sent_at = 0;
  out->config_hash = 0;
  out->restart_on_update = 0;
  out->exec = strdup(exec_path);
  if (set_socket_nonblocking(out->fd_read, 0) != 0 || set_socket_nonblocking(out->fd_write, 0) != 0) {
    plugin_state_free(out);
    return -1;
  }
  return 0;
}

static int do_discovery(plugin_state_t *p) {
  if (!discovery_cmd_used) return 0;
  resp_object disc_obj = { .type = RESPT_BULK, .u = { .s = (char *)discovery_cmd_used } };
  const resp_object *av[] = { &disc_obj };
  char *req = NULL;
  size_t req_len;
  if (resp_encode_array(1, av, &req, &req_len) != 0) return -1;
  ssize_t n = write(p->fd_write, req, req_len);
  free(req);
  if (n != (ssize_t)req_len) return -1;
  resp_object *r = resp_read(p->fd_read);
  if (!r || r->type != RESPT_ARRAY) {
    if (r) resp_free(r);
    return -1;
  }
  for (size_t i = 0; i < r->u.arr.n; i++) {
    resp_object *e = &r->u.arr.elem[i];
    const char *s = (e->type == RESPT_BULK || e->type == RESPT_SIMPLE) ? e->u.s : NULL;
    if (!s) continue;
    char **new_m = realloc(p->methods, (p->method_count + 1) * sizeof(char *));
    if (!new_m) break;
    p->methods = new_m;
    p->methods[p->method_count++] = strdup(s);
  }
  resp_free(r);
  return 0;
}

void plugmod_start(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd,
  plugmod_after_discovery_fn after_discovery_cb, void *after_discovery_user) {
  log_trace("plugmod_start: %zu plugin configs, discovery=%s", n, discovery_cmd ? discovery_cmd : "(none)");
  discovery_cmd_used = discovery_cmd;
  after_discovery_cb_used = after_discovery_cb;
  after_discovery_user_used = after_discovery_user;
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
    p->restart_on_update = configs[i].restart_on_update;
    if (discovery_cmd_used && do_discovery(p) != 0) {
      log_error("plugin %s: discovery failed", p->name);
      plugin_state_free(p);
      continue;
    }
    if (after_discovery_cb_used)
      after_discovery_cb_used(p->name, after_discovery_user_used);
    log_debug("plugin %s: %zu methods", p->name, p->method_count);
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

int plugmod_start_plugin(const char *name, const char *exec, unsigned long long config_hash, int restart_on_update) {
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
  p->restart_on_update = restart_on_update;
  if (do_discovery(p) != 0) {
    log_error("plugin %s: discovery failed", p->name);
    plugin_state_free(p);
    return -1;
  }
  if (after_discovery_cb_used)
    after_discovery_cb_used(p->name, after_discovery_user_used);
  log_debug("plugin %s: %zu methods", p->name, p->method_count);
  plugin_n++;
  return 0;
}

void plugmod_sync(const plugmod_config_item *configs, size_t n,
  const char *discovery_cmd,
  plugmod_after_discovery_fn after_discovery_cb, void *after_discovery_user) {
  plugmod_tick();
  discovery_cmd_used = discovery_cmd;
  after_discovery_cb_used = after_discovery_cb;
  after_discovery_user_used = after_discovery_user;
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
    if (c->restart_on_update != p->restart_on_update) {
      plugmod_stop_plugin(p->name);
      continue;
    }
    if (c->config_hash != 0 && p->config_hash != c->config_hash) {
      if (c->restart_on_update) {
        plugmod_stop_plugin(p->name);
        continue;
      }
      if (after_discovery_cb_used)
        after_discovery_cb_used(p->name, after_discovery_user_used);
      p->config_hash = c->config_hash;
      p->restart_on_update = c->restart_on_update;
    }
  }
  for (size_t j = 0; j < n; j++) {
    if (!configs[j].exec || !configs[j].exec[0]) continue;
    if (find_plugin(configs[j].name) != NULL) continue;
    plugmod_start_plugin(configs[j].name, configs[j].exec, configs[j].config_hash, configs[j].restart_on_update);
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

int plugmod_invoke_response(const char *plugin_name, const char *method, int argc, const resp_object *const *argv,
  resp_object **out) {
  plugin_state_t *p = find_plugin(plugin_name);
  if (!p || p->stopping || !out) return -1;
  *out = NULL;
  resp_object method_obj = { .type = RESPT_BULK, .u = { .s = (char *)method } };
  const resp_object *arr[256];
  int n = argc + 1;
  if (n > 256) return -1;
  arr[0] = &method_obj;
  for (int i = 0; i < argc; i++) arr[i + 1] = argv[i];
  char *buf = NULL;
  size_t len = 0;
  if (resp_encode_array(n, arr, &buf, &len) != 0) return -1;
  if (write(p->fd_write, buf, len) != (ssize_t)len) {
    free(buf);
    return -1;
  }
  free(buf);
  *out = resp_read(p->fd_read);
  return (*out) ? 0 : -1;
}

int plugmod_invoke(const char *plugin_name, const char *method, int argc, const resp_object *const *argv) {
  log_debug("plugin call: %s -> %s (%d args)", plugin_name, method, argc);
  resp_object *r = NULL;
  int ret = plugmod_invoke_response(plugin_name, method, argc, argv, &r);
  if (r) resp_free(r);
  return ret;
}

int plugmod_has_method(const char *plugin_name, const char *method_name) {
  plugin_state_t *p = find_plugin(plugin_name);
  if (!p || p->stopping) return 0;
  for (size_t i = 0; i < p->method_count; i++)
    if (strcasecmp(p->methods[i], method_name) == 0)
      return 1;
  return 0;
}

void plugmod_notify_event(const char *event_name, int argc, const resp_object *const *argv) {
  log_debug("plugin event %s (%d args)", event_name, argc);
  for (size_t i = 0; i < plugin_n; i++) {
    if (plugins[i].stopping) continue;
    if (!plugmod_has_method(plugins[i].name, event_name)) continue;
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
