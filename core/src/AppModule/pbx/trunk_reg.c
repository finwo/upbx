#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "rxi/log.h"
#include "common/pt.h"
#include "common/socket_util.h"
#include "config.h"
#include "AppModule/scheduler/daemon.h"
#include "AppModule/pbx/trunk_reg.h"
#include "AppModule/pbx/registration.h"
#include "PluginModule/plugin.h"

#define MAX_TRUNKS 64

static trunk_reg_t *trunks[MAX_TRUNKS];
static size_t trunk_count = 0;

void trunk_reg_notify_plugins(void);

static trunk_reg_t *find_trunk(const char *name) {
  for (size_t i = 0; i < trunk_count; i++) {
    if (trunks[i] && strcmp(trunks[i]->name, name) == 0) {
      return trunks[i];
    }
  }
  return NULL;
}

static int send_register(trunk_reg_t *t) {
  if (t->fd < 0) return -1;
  
  char req[1024];
  int len = snprintf(req, sizeof(req),
    "REGISTER sip:%s:%d SIP/2.0\r\n"
    "Via: SIP/2.0/%s %s:%d;branch=z9hG4bK%llx\r\n"
    "From: <sip:%s@%s>;tag=%llx\r\n"
    "To: <sip:%s@%s>\r\n"
    "Call-ID: %llx\r\n"
    "CSeq: 1 REGISTER\r\n"
    "Contact: <sip:%s@%s:%d>\r\n"
    "Expires: 300\r\n"
    "Authorization: Digest username=\"%s\",realm=\"*\",nonce=\"\",uri=\"sip:%s:%d\"\r\n"
    "Content-Length: 0\r\n"
    "\r\n",
    t->host, t->port,
    t->transport, t->via_addr, t->via_port, (unsigned long long)time(NULL),
    t->username, t->host,
    (unsigned long long)time(NULL),
    t->username, t->host,
    (unsigned long long)time(NULL),
    t->username, t->via_addr, t->via_port,
    t->username, t->host, t->port
  );
  
  if (write(t->fd, req, len) != len) {
    log_error("trunk %s: failed to send REGISTER", t->name);
    return -1;
  }
  
  return 0;
}

PT_THREAD(trunk_reg_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  trunk_reg_t *t = task->udata;
  
  PT_BEGIN(pt);
  
  PT_INIT(&t->pt);
  
  struct hostent *he = gethostbyname(t->host);
  if (!he) {
    log_error("trunk %s: DNS lookup failed for %s", t->name, t->host);
    PT_EXIT(pt);
  }
  
  t->fd = socket(AF_INET, strcmp(t->transport, "tcp") == 0 ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (t->fd < 0) {
    log_error("trunk %s: socket failed", t->name);
    PT_EXIT(pt);
  }
  
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, he->h_addr, he->h_length);
  addr.sin_port = htons(t->port);
  
  if (strcmp(t->transport, "tcp") == 0) {
    if (connect(t->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      log_error("trunk %s: connect failed", t->name);
      close(t->fd);
      t->fd = -1;
      PT_EXIT(pt);
    }
    set_socket_nonblocking(t->fd, 1);
  } else {
    if (bind(t->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      log_error("trunk %s: bind failed", t->name);
      close(t->fd);
      t->fd = -1;
      PT_EXIT(pt);
    }
  }
  
  task->read_fds = &t->fd;
  task->read_fds_count = 1;
  
  log_info("trunk %s: starting registration to %s:%d (%s)", t->name, t->host, t->port, t->transport);
  
  if (send_register(t) != 0) {
    close(t->fd);
    t->fd = -1;
    PT_EXIT(pt);
  }
  
  for (;;) {
    int ready_fd = -1;
    PT_WAIT_UNTIL(pt, pt_task_has_data(task, &ready_fd) == 0 && ready_fd == t->fd);
    
    char buf[512];
    ssize_t n = read(t->fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
      if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        log_error("trunk %s: connection lost", t->name);
        break;
      }
    }
    
    buf[n] = '\0';
    if (strstr(buf, "200 OK")) {
      t->registered = 1;
      t->expires = time(NULL) + 300;
      log_info("trunk %s: registered", t->name);
    }
    
    (void)timestamp;
  }
  
  if (t->fd >= 0) {
    close(t->fd);
    t->fd = -1;
  }
  
  PT_END(pt);
}

void trunk_reg_start_all(void) {
  if (!global_cfg) return;
  
  for (size_t i = 0; i < 256; i++) {
    char key[32];
    snprintf(key, sizeof(key), "trunk:%zu", i);
    resp_object *sec = resp_map_get(global_cfg, key);
    if (!sec || sec->type != RESPT_ARRAY) {
      continue;
    }
    
    const char *name = NULL;
    const char *host = NULL;
    int port = 5060;
    const char *transport = "udp";
    const char *username = NULL;
    const char *password = NULL;
    
    for (size_t j = 0; j + 1 < sec->u.arr.n; j += 2) {
      if (sec->u.arr.elem[j].type != RESPT_BULK) continue;
      const char *k = sec->u.arr.elem[j].u.s;
      if (!k) continue;
      if (sec->u.arr.elem[j+1].type != RESPT_BULK) continue;
      const char *v = sec->u.arr.elem[j+1].u.s;
      if (!v) continue;
      
      if (strcmp(k, "name") == 0) name = v;
      else if (strcmp(k, "host") == 0) host = v;
      else if (strcmp(k, "port") == 0) port = atoi(v);
      else if (strcmp(k, "transport") == 0) transport = v;
      else if (strcmp(k, "username") == 0) username = v;
      else if (strcmp(k, "password") == 0) password = v;
    }
    
    if (name && host && trunk_count < MAX_TRUNKS) {
      trunk_reg_t *t = calloc(1, sizeof(*t));
      t->name = strdup(name);
      t->host = strdup(host);
      t->port = port;
      strncpy(t->transport, transport, sizeof(t->transport) - 1);
      t->username = username ? strdup(username) : NULL;
      t->password = password ? strdup(password) : NULL;
      t->fd = -1;
      t->via_addr = "0.0.0.0";
      t->via_port = 0;
      
      appmodule_pt_add(trunk_reg_pt, t);
      trunks[trunk_count++] = t;
      
      log_info("trunk %s: created registration PT", name);
    }
    
    resp_free(sec);
  }
  
  trunk_reg_notify_plugins();
}

void trunk_reg_stop_all(void) {
  for (size_t i = 0; i < trunk_count; i++) {
    trunk_reg_t *t = trunks[i];
    if (t->fd >= 0) {
      close(t->fd);
      t->fd = -1;
    }
    free(t->name);
    free(t->host);
    free(t->username);
    free(t->password);
    free(t);
    trunks[i] = NULL;
  }
  trunk_count = 0;
}

void trunk_reg_tick(void) {
  time_t now = time(NULL);
  for (size_t i = 0; i < trunk_count; i++) {
    trunk_reg_t *t = trunks[i];
    if (t && t->registered && t->expires > 0 && t->expires - now < 60) {
      log_info("trunk %s: refreshing registration", t->name);
      if (t->fd >= 0) {
        send_register(t);
      }
    }
  }
}

trunk_reg_t *trunk_reg_find(const char *name) {
  return find_trunk(name);
}

const char *trunk_reg_get_contact(const char *name) {
  trunk_reg_t *t = find_trunk(name);
  return t ? t->contact : NULL;
}

int trunk_reg_is_registered(const char *name) {
  trunk_reg_t *t = find_trunk(name);
  return t && t->registered;
}

int trunk_reg_is_available(const char *name) {
  trunk_reg_t *t = find_trunk(name);
  return t && t->registered && t->expires > time(NULL);
}

void trunk_reg_notify_plugins(void) {
  if (!global_cfg) return;
  
  resp_object *list = resp_array_init();
  
  for (size_t i = 0; i < trunk_count; i++) {
    trunk_reg_t *t = trunks[i];
    resp_object *trunk_obj = resp_array_init();
    resp_array_append_bulk(trunk_obj, "name");
    resp_array_append_bulk(trunk_obj, t->name ? t->name : "");
    resp_array_append_bulk(trunk_obj, "host");
    resp_array_append_bulk(trunk_obj, t->host ? t->host : "");
    resp_array_append_obj(list, trunk_obj);
  }
  
  resp_object *argv[] = { list };
  plugmod_notify_event("trunk.list", 1, (const resp_object *const *)&argv);
  resp_free(list);
}