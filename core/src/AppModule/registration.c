/*
 * Extension registration state management.
 * Tracks which SIP extensions are currently registered, on which trunk.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "rxi/log.h"
#include "common/pt.h"
#include "AppModule/registration.h"
#include "AppModule/command/daemon.h"

#define DEFAULT_EXPIRES 300  /* 5 minutes */

static ext_reg_t *reg_list;
static size_t reg_count;
static size_t reg_cap;
static int reg_list_ready;
static int reg_list_notify_pending;

static char learned_advertise_host[256];
static char learned_advertise_port[32];

void registration_init(void) {
  reg_list = NULL;
  reg_count = 0;
  reg_cap = 0;
  reg_list_ready = 0;
  reg_list_notify_pending = 0;
  learned_advertise_host[0] = '\0';
  learned_advertise_port[0] = '\0';
}

static void registration_set_ready(void) { reg_list_ready = 1; }

static void registration_set_notify_pending(void)   { reg_list_notify_pending = 1; }
void registration_clear_notify_pending(void) { reg_list_notify_pending = 0; }
int  registration_is_notify_pending(void)    { return reg_list_notify_pending; }

void registration_update(char *number, char *uri_user, const char *trunk_name,
    char *contact, const char *learned_host, const char *learned_port,
    const char *src_host, const char *src_port,
    char *plugin_data, const char *transport) {
  log_trace("%s: number=%s", __func__, number ? number : "(null)");

  registration_set_ready();

  /* Try to find existing entry for this extension number. */
  for (size_t i = 0; i < reg_count; i++) {
    if (strcmp(reg_list[i].number, number) == 0) {
      /* Update existing. Free old strings, take ownership of new ones. */
      free(reg_list[i].trunk_name);
      free(reg_list[i].contact);
      free(reg_list[i].uri_user);
      free(reg_list[i].plugin_data);
      reg_list[i].trunk_name = trunk_name ? strdup(trunk_name) : strdup("");
      reg_list[i].contact = contact ? contact : strdup("");
      reg_list[i].uri_user = uri_user;
      reg_list[i].plugin_data = plugin_data;
      reg_list[i].expires = time(NULL) + DEFAULT_EXPIRES;
      if (learned_host && learned_host[0]) {
        strncpy(reg_list[i].learned_host, learned_host, sizeof(reg_list[i].learned_host) - 1);
        reg_list[i].learned_host[sizeof(reg_list[i].learned_host) - 1] = '\0';
        strncpy(reg_list[i].learned_port, (learned_port && learned_port[0]) ? learned_port : "5060",
            sizeof(reg_list[i].learned_port) - 1);
        reg_list[i].learned_port[sizeof(reg_list[i].learned_port) - 1] = '\0';
      } else {
        reg_list[i].learned_host[0] = '\0';
      }
      if (src_host && src_host[0]) {
        memset(&reg_list[i].remote_addr, 0, sizeof(reg_list[i].remote_addr));
        reg_list[i].remote_addr.sin_family = AF_INET;
        inet_pton(AF_INET, src_host, &reg_list[i].remote_addr.sin_addr);
        if (src_port && src_port[0]) {
          reg_list[i].remote_addr.sin_port = htons((uint16_t)atoi(src_port));
        }
      }
      if (transport && strcasecmp(transport, "tcp") == 0) {
        memcpy(reg_list[i].transport, "tcp", 3);
      } else {
        memcpy(reg_list[i].transport, "udp", 3);
      }
      reg_list[i].transport[3] = '\0';
      reg_list[i].tcp_sock = 0;  /* Reset TCP socket on re-registration */
      /* number was already owned by the old entry; free the duplicate passed in */
      free(number);
      registration_set_notify_pending();
      return;
    }
  }

  /* New entry: grow array if needed. */
  if (reg_count >= reg_cap) {
    size_t newcap = reg_cap ? reg_cap * 2 : 8;
    ext_reg_t *new_list = realloc(reg_list, newcap * sizeof(ext_reg_t));
    if (!new_list) {
      log_error("registration: realloc failed");
      free(number); free(uri_user); free(contact); free(plugin_data);
      return;
    }
    reg_list = new_list;
    reg_cap = newcap;
  }

  reg_list[reg_count].number = number;
  reg_list[reg_count].uri_user = uri_user;
  reg_list[reg_count].trunk_name = trunk_name ? strdup(trunk_name) : strdup("");
  reg_list[reg_count].contact = contact ? contact : strdup("");
  if (learned_host && learned_host[0]) {
    strncpy(reg_list[reg_count].learned_host, learned_host, sizeof(reg_list[reg_count].learned_host) - 1);
    reg_list[reg_count].learned_host[sizeof(reg_list[reg_count].learned_host) - 1] = '\0';
    strncpy(reg_list[reg_count].learned_port, (learned_port && learned_port[0]) ? learned_port : "5060",
        sizeof(reg_list[reg_count].learned_port) - 1);
    reg_list[reg_count].learned_port[sizeof(reg_list[reg_count].learned_port) - 1] = '\0';
  } else {
    reg_list[reg_count].learned_host[0] = '\0';
  }
  if (src_host && src_host[0]) {
    memset(&reg_list[reg_count].remote_addr, 0, sizeof(reg_list[reg_count].remote_addr));
    reg_list[reg_count].remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, src_host, &reg_list[reg_count].remote_addr.sin_addr);
    if (src_port && src_port[0]) {
      reg_list[reg_count].remote_addr.sin_port = htons((uint16_t)atoi(src_port));
    }
  }
  reg_list[reg_count].plugin_data = plugin_data;
  reg_list[reg_count].expires = time(NULL) + DEFAULT_EXPIRES;
  if (transport && strcasecmp(transport, "tcp") == 0) {
    memcpy(reg_list[reg_count].transport, "tcp", 3);
  } else {
    memcpy(reg_list[reg_count].transport, "udp", 3);
  }
  reg_list[reg_count].transport[3] = '\0';
  reg_list[reg_count].tcp_sock = 0;
  reg_count++;

  registration_set_notify_pending();
}

ext_reg_t *registration_get_by_number(const char *trunk_name, const char *number) {
  time_t now = time(NULL);
  if (!reg_list_ready || !reg_list || !number) return NULL;
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (trunk_name && reg_list[i].trunk_name && strcmp(reg_list[i].trunk_name, trunk_name) != 0) continue;
    if (strcmp(reg_list[i].number, number) == 0)
      return &reg_list[i];
  }
  return NULL;
}

size_t registration_get_regs(const char *trunk_name, const char *ext_number, ext_reg_t ***out) {
  ext_reg_t **list = NULL;
  size_t n = 0;
  time_t now = time(NULL);
  if (!reg_list_ready || !reg_list || !out) return 0;
  *out = NULL;
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (trunk_name && strcmp(reg_list[i].trunk_name, trunk_name) != 0) continue;
    if (ext_number && strcmp(reg_list[i].number, ext_number) != 0) continue;
    ext_reg_t **new_list = (ext_reg_t **)realloc(list, (n + 1) * sizeof(ext_reg_t *));
    if (!new_list) break;
    list = new_list;
    list[n++] = &reg_list[i];
  }
  *out = list;
  return n;
}

const char *registration_get_trunk_for_ext(const char *ext_number) {
  time_t now = time(NULL);
  if (!reg_list_ready || !ext_number || !reg_list) return "";
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (strcmp(reg_list[i].number, ext_number) == 0)
      return reg_list[i].trunk_name ? reg_list[i].trunk_name : "";
  }
  return "";
}

void registration_set_advertise_addr(const char *host, const char *port) {
  if (host) {
    strncpy(learned_advertise_host, host, sizeof(learned_advertise_host) - 1);
    learned_advertise_host[sizeof(learned_advertise_host) - 1] = '\0';
  }
  if (port && port[0]) {
    strncpy(learned_advertise_port, port, sizeof(learned_advertise_port) - 1);
    learned_advertise_port[sizeof(learned_advertise_port) - 1] = '\0';
  } else {
    strncpy(learned_advertise_port, "5060", sizeof(learned_advertise_port));
  }
}

int registration_get_advertise_addr(char *host_out, size_t host_size, char *port_out, size_t port_size) {
  if (!learned_advertise_host[0]) return 0;
  size_t n = strlen(learned_advertise_host);
  if (n >= host_size) return 0;
  memcpy(host_out, learned_advertise_host, n + 1);
  n = strlen(learned_advertise_port);
  if (n > 0 && n < port_size)
    memcpy(port_out, learned_advertise_port, n + 1);
  else if (port_size > 0)
    memcpy(port_out, "5060", 5 < port_size ? 5 : port_size);
  return 1;
}

void registration_set_tcp_sock(ext_reg_t *reg, int sock) {
  if (reg) reg->tcp_sock = sock;
}

int registration_get_tcp_sock(const ext_reg_t *reg) {
  if (!reg || strcmp(reg->transport, "tcp") != 0) return -1;
  return reg->tcp_sock;
}

ext_reg_t *registration_get_by_tcp_sock(int sockfd) {
  if (sockfd <= 0) return NULL;
  time_t now = time(NULL);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (reg_list[i].tcp_sock > 0 && reg_list[i].tcp_sock == sockfd) {
      return &reg_list[i];
    }
  }
  return NULL;
}

int registration_fill_tcp_fds(fd_set *read_set, int *maxfd) {
  int count = 0;
  time_t now = time(NULL);
  for (size_t i = 0; i < reg_count; i++) {
    if (reg_list[i].expires <= now) continue;
    if (reg_list[i].tcp_sock > 0) {
      FD_SET(reg_list[i].tcp_sock, read_set);
      if (reg_list[i].tcp_sock > *maxfd) *maxfd = reg_list[i].tcp_sock;
      count++;
    }
  }
  return count;
}

/* Expiry removal protothread: wait 60s, then remove expired entries, repeat. */
static time_t next_reg_expiry_check = 0;

PT_THREAD(registration_remove_expired_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  time_t loop_timestamp = 0;
  PT_BEGIN(pt);
  for (;;) {
    loop_timestamp = (time_t)(timestamp / 1000);
    PT_WAIT_UNTIL(pt, next_reg_expiry_check == 0 || loop_timestamp >= next_reg_expiry_check);
    next_reg_expiry_check = loop_timestamp + 60;

    time_t now = time(NULL);
    size_t w = 0;
    for (size_t i = 0; i < reg_count; i++) {
      if (reg_list[i].expires <= now) {
        free(reg_list[i].number);
        free(reg_list[i].trunk_name);
        free(reg_list[i].contact);
        free(reg_list[i].uri_user);
        free(reg_list[i].plugin_data);
      } else {
        if (w != i)
          reg_list[w] = reg_list[i];
        w++;
      }
    }
    if (w != reg_count)
      registration_set_notify_pending();
    reg_count = w;
    PT_YIELD(pt);
  }
  PT_END(pt);
}

static void __attribute__((constructor)) registration_register(void) {
  appmodule_pt_add(registration_remove_expired_pt, NULL);
}

