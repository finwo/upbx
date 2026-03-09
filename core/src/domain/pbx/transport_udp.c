#include "domain/pbx/transport_udp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "common/hexdump.h"
#include "common/scheduler.h"
#include "common/socket_util.h"
#include "common/socket_util.h"
#include "domain/config.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/sip_handler.h"
#include "domain/pbx/sip_parser.h"
#include "rxi/log.h"

typedef struct {
  int initialized;
  int *fds;
  char recv_buf[4096];
} pbx_transport_udata_t;

static char *extract_extension_from_uri(const char *uri) {
  if (!uri) return NULL;
  const char *start = uri;
  if (start[0] == '<') {
    start++;
    const char *end = strchr(start, '>');
    if (end) {
      size_t len = (size_t)(end - start);
      char *tmp = malloc(len + 1);
      memcpy(tmp, start, len);
      tmp[len] = '\0';
      char *result = extract_extension_from_uri(tmp);
      free(tmp);
      return result;
    }
  }
  if (strncmp(start, "sip:", 4) == 0) {
    const char *user = start + 4;
    const char *at = strchr(user, '@');
    if (at) {
      return strndup(user, at - user);
    }
  }
  return NULL;
}

static char *extract_extension_from_from_header(const sip_message_t *msg) {
  if (!msg || !msg->from) return NULL;
  const char *from = msg->from;
  if (strncmp(from, "sip:", 4) == 0) {
    return extract_extension_from_uri(from + 4);
  }
  return extract_extension_from_uri(from);
}

static void pbx_sip_context_resolve_registration(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;
  if (!msg || !msg->method) {
    ctx->reg = NULL;
    return;
  }

  int is_register = (strcmp(msg->method, "REGISTER") == 0);

  if (is_register) {
    char *extension = sip_request_uri_user_from_to(msg);
    if (extension) {
      pbx_registration_t *reg = pbx_registration_find(extension);
      if (reg) {
        char *host_port = sip_request_uri_host_port(msg);
        if (host_port) {
          pbx_registration_update_pbx_addr(extension, host_port);
          free(host_port);
        }
        ctx->reg = reg;
      }
      free(extension);
    }
    return;
  }

  int status_code = sip_response_status_code(msg);
  if (status_code > 0) {
    ctx->reg = pbx_registration_find_by_remote_addr((struct sockaddr *)&ctx->remote_addr);
    return;
  }

  pbx_registration_t *reg = pbx_registration_find_by_remote_addr((struct sockaddr *)&ctx->remote_addr);
  if (!reg) {
    ctx->reg = NULL;
    return;
  }

  char *from_ext = extract_extension_from_from_header(msg);
  if (from_ext && strcmp(from_ext, reg->extension) == 0) {
    char *host_port = sip_request_uri_host_port(msg);
    if (host_port) {
      pbx_registration_update_pbx_addr(reg->extension, host_port);
      free(host_port);
    }
    ctx->reg = reg;
  } else {
    log_warn("pbx: registration lookup - From header %s doesn't match registration %s", 
              from_ext ? from_ext : "(null)", reg->extension);
    free(reg);
    ctx->reg = NULL;
  }
  free(from_ext);
}

int sip_transport_udp_pt(int64_t timestamp, struct pt_task *task) {
  pbx_transport_udata_t *udata = (pbx_transport_udata_t *)task->udata;

  (void)timestamp;

  if (!udata) {
    udata = calloc(1, sizeof(pbx_transport_udata_t));
    task->udata = udata;
  }

  if (!udata->initialized) {
    const char *listen_addr = "5060";
    if (domain_cfg) {
      const char *val = resp_map_get_string(domain_cfg, "listen");
      if (val) listen_addr = val;
    }

    udata->fds = udp_recv(listen_addr, NULL, NULL);
    if (!udata->fds || udata->fds[0] == 0) {
      log_error("pbx: failed to create UDP listening socket on %s", listen_addr);
      return SCHED_ERROR;
    }

    for (int i = 1; i <= udata->fds[0]; i++) {
      log_info("pbx: SIP UDP listening on fd %d", udata->fds[i]);
    }

    udata->initialized = 1;
  }

  int ready_fd = sched_has_data(udata->fds);
  if (ready_fd <= 0) {
    return SCHED_RUNNING;
  }

  struct sockaddr_storage remote_addr;
  socklen_t addr_len = sizeof(remote_addr);
  ssize_t n = recvfrom(ready_fd, udata->recv_buf, sizeof(udata->recv_buf) - 1, 0,
                        (struct sockaddr *)&remote_addr, &addr_len);

  if (n > 0) {
    udata->recv_buf[n] = '\0';
    char remote_addr_str[128] = "";
    sockaddr_to_string((struct sockaddr *)&remote_addr, remote_addr_str, sizeof(remote_addr_str));
    log_trace("pbx: received %zd bytes from SIP UDP (from=%s)", n, remote_addr_str);
    log_hexdump_trace(udata->recv_buf, n);

    sip_message_t *msg = sip_parse(udata->recv_buf, (size_t)n);
    if (msg) {
      pbx_sip_context_t ctx = {
        .fd = ready_fd,
        .remote_addr = remote_addr,
        .msg = msg,
        .reg = NULL
      };
      pbx_sip_context_resolve_registration(&ctx);
      pbx_sip_handle(&ctx);
      if (ctx.reg) {
        free(ctx.reg);
      }
      sip_message_free(msg);
    }
  }

  return SCHED_RUNNING;
}
