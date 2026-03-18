#include "pbx/trunk.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common/digest_auth.h"
#include "finwo/socket-util.h"

struct pbx_trunk *pbx_trunk_create(struct upbx_config *config) {
  struct pbx_trunk *trunks = NULL;

  for (struct upbx_trunk *t = config->trunks; t; t = t->next) {
    struct pbx_trunk *node = calloc(1, sizeof(*node));
    node->config = config;
    node->config_trunk = t;
    node->registered = 0;
    node->fd = -1;

    node->next = trunks;
    trunks = node;
  }

  return trunks;
}

void pbx_trunk_destroy(struct pbx_trunk *trunks) {
  struct pbx_trunk *t = trunks;
  while (t) {
    struct pbx_trunk *next = t->next;
    if (t->fd >= 0) {
      close(t->fd);
    }
    free(t->registered_contact);
    free(t);
    t = next;
  }
}

static int connect_trunk(struct pbx_trunk *trunk) {
  if (!trunk || !trunk->config_trunk || !trunk->config_trunk->address) {
    return -1;
  }

  struct parsed_url *url = trunk->config_trunk->address;

  if (trunk->fd >= 0) {
    close(trunk->fd);
    trunk->fd = -1;
  }

  if (url->scheme && strcmp(url->scheme, "sip") == 0) {
    const char *host = url->host ? url->host : "localhost";
    const char *port = url->port ? url->port : "5060";

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
      return -1;
    }

    trunk->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (trunk->fd < 0) {
      freeaddrinfo(res);
      return -1;
    }

    if (connect(trunk->fd, res->ai_addr, res->ai_addrlen) < 0) {
      close(trunk->fd);
      trunk->fd = -1;
      freeaddrinfo(res);
      return -1;
    }

    freeaddrinfo(res);
    return 0;
  }

  return -1;
}

int pbx_trunk_register(struct pbx_trunk *trunk, struct upbx_trunk *config_trunk) {
  if (!trunk || !config_trunk) return -1;

  trunk->config_trunk = config_trunk;

  if (trunk->fd < 0) {
    if (connect_trunk(trunk) != 0) {
      return -1;
    }
  }

  char call_id[64];
  snprintf(call_id, sizeof(call_id), "upbx-%ld-%p", (long)time(NULL), (void *)trunk);

  char contact[256];
  snprintf(contact, sizeof(contact), "sip:upbx@%s:%d", "127.0.0.1", 5060);

  char req[1024];
  snprintf(req, sizeof(req),
    "REGISTER %s SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK\r\n"
    "From: <sip:upbx@%s>\r\n"
    "To: <sip:upbx@%s>\r\n"
    "Call-ID: %s\r\n"
    "CSeq: 1 REGISTER\r\n"
    "Contact: %s\r\n"
    "Expires: 60\r\n"
    "Content-Length: 0\r\n"
    "\r\n",
    config_trunk->address->host ? config_trunk->address->host : "localhost",
    config_trunk->address->host ? config_trunk->address->host : "localhost",
    call_id,
    contact
  );

  if (send(trunk->fd, req, strlen(req), 0) < 0) {
    return -1;
  }

  trunk->last_register_attempt = time(NULL);
  return 0;
}

int pbx_trunk_handle_response(struct pbx_trunk *trunk, const char *call_id, int status_code, const char *auth_header) {
  (void)call_id;
  (void)auth_header;

  if (!trunk) return -1;

  if (status_code == 200) {
    trunk->registered = 1;
    trunk->registration_expires = time(NULL) + 60;
  }

  return 0;
}

struct pbx_trunk *pbx_trunk_find_by_name(struct pbx_trunk *trunks, const char *name) {
  for (struct pbx_trunk *t = trunks; t; t = t->next) {
    if (t->config_trunk && strcmp(t->config_trunk->name, name) == 0) {
      return t;
    }
  }
  return NULL;
}

struct pbx_trunk *pbx_trunk_find_by_contact(struct pbx_trunk *trunks, const char *contact) {
  for (struct pbx_trunk *t = trunks; t; t = t->next) {
    if (t->registered_contact && contact && strcmp(t->registered_contact, contact) == 0) {
      return t;
    }
  }
  return NULL;
}

int pbx_trunk_get_fds(struct pbx_trunk *trunks, int **fds) {
  if (!fds) return 0;

  int count = 0;
  for (struct pbx_trunk *t = trunks; t; t = t->next) {
    if (t->fd >= 0) count++;
  }

  if (count == 0) return 0;

  *fds = malloc(sizeof(int) * (count + 1));
  (*fds)[0] = count;

  int idx = 1;
  for (struct pbx_trunk *t = trunks; t; t = t->next) {
    if (t->fd >= 0) {
      (*fds)[idx++] = t->fd;
    }
  }

  return count;
}

int pbx_trunk_send(struct pbx_trunk *trunk, const char *data, size_t len) {
  if (!trunk || trunk->fd < 0 || !data) return -1;
  return (send(trunk->fd, data, len, 0) == (ssize_t)len) ? 0 : -1;
}
