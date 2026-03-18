#ifndef SIP_LISTENER_H
#define SIP_LISTENER_H

#include <stdbool.h>
#include <sys/socket.h>

#include "config/config.h"
#include "sip/parser.h"

typedef void (*sip_request_cb)(struct sip_request *req, const struct sockaddr_storage *src, const char *local_addr, void *udata);

struct sip_listener {
  struct upbx_config *config;

  int *fds;

  sip_request_cb on_request;
  void *user_data;
};

struct sip_listener *sip_listener_create(struct upbx_config *config);
void sip_listener_destroy(struct sip_listener *listener);
int sip_listener_listen(struct sip_listener *listener, const char *addr);
int sip_listener_set_handler(struct sip_listener *listener, sip_request_cb cb, void *udata);
int *sip_listener_get_fds(struct sip_listener *listener);
int sip_listener_send(struct sip_listener *listener, const struct sockaddr_storage *dst, const char *data, size_t len);
int sip_listener_process(struct sip_listener *listener);

#endif // SIP_LISTENER_H
