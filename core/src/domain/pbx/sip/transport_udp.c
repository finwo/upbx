#include "domain/pbx/sip/transport_udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common/hexdump.h"
#include "common/scheduler.h"
#include "common/socket_util.h"
#include "domain/config.h"
#include "domain/pbx/call.h"
#include "domain/pbx/group.h"
#include "domain/pbx/nonce.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sip_message.h"
#include "domain/pbx/sip/sip_proto.h"
#include "domain/pbx/sip_handler.h"
#include "infrastructure/config.h"
#include "rxi/log.h"

#define UDP_BUF_SIZE 8192

int *sip_fds = NULL;

typedef struct {
  int                     state;
  char                    buf[UDP_BUF_SIZE];
  struct sockaddr_storage src_addr;
  socklen_t               src_len;
  sip_message_t           sip_msg;
  int                     current_fd_idx;
} sip_udp_udata_t;

typedef struct {
  const char  *method;
  size_t      method_len;
  sip_method_handler handler;
} sip_handler_entry;

static const sip_handler_entry sip_handlers[] = {
  {"REGISTER",  8, sip_handle_register},
  {"INVITE",    6, call_handle_invite},
  {"BYE",       3, call_handle_bye},
  {"CANCEL",    6, call_handle_cancel},
  {"ACK",       3, NULL},
  {"OPTIONS",   7, NULL},
};

void sip_transport_udp_set_fds(int *fds) {
  sip_fds = fds;
}

static char *sip_dispatch(sip_message_t *msg, const struct sockaddr_storage *remote_addr, int listen_fd, size_t *response_len) {
  if (!msg || !sip_is_request(msg) || !response_len) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len, NULL);
  }

  for (size_t i = 0; i < sizeof(sip_handlers) / sizeof(sip_handlers[0]); i++) {
    if (msg->method_len == sip_handlers[i].method_len &&
        strncasecmp(msg->method, sip_handlers[i].method, msg->method_len) == 0) {

      registration_t *reg = registration_find_by_addr((const struct sockaddr *)remote_addr);

      if (sip_handlers[i].handler) {
        return sip_handlers[i].handler(msg, remote_addr, reg, listen_fd, response_len);
      }

      if (msg->method_len == 3 && strncasecmp(msg->method, "ACK", 3) == 0) {
        log_trace("transport_udp: ACK received, no response needed");
        return NULL;
      }

      if (msg->method_len == 7 && strncasecmp(msg->method, "OPTIONS", 7) == 0) {
        return sip_proto_build_response(msg, 405, "Method Not Allowed", NULL, NULL, 0, response_len, NULL);
      }

      return sip_proto_build_response(msg, 405, "Method Not Allowed", NULL, NULL, 0, response_len, NULL);
    }
  }

  return sip_proto_build_response(msg, 405, "Method Not Allowed", NULL, NULL, 0, response_len, NULL);
}

int sip_transport_udp_pt(int64_t timestamp, struct pt_task *task) {
  (void)timestamp;
  sip_udp_udata_t *udata = task->udata;

  if (!udata) {
    udata = calloc(1, sizeof(sip_udp_udata_t));
    if (!udata) return SCHED_ERROR;
    task->udata = udata;
  }

  if (udata->state == 0) {
    if (!domain_cfg) {
      return SCHED_RUNNING;
    }

    resp_object *upbx_sec = resp_map_get(domain_cfg, "upbx");
    resp_object *addr_arr = upbx_sec ? resp_map_get(upbx_sec, "address") : NULL;

    const char *listen_str = NULL;
    if (addr_arr && addr_arr->type == RESPT_ARRAY && addr_arr->u.arr.n > 0) {
      listen_str = addr_arr->u.arr.elem[0].u.s;
      if (!listen_str || !listen_str[0]) {
        listen_str = ":5060";
      }
    } else {
      listen_str = ":5060";
    }
    if (strncmp(listen_str, "udp://", 6) == 0) {
      listen_str = listen_str + 6;
    }

    const char *secret = upbx_sec ? resp_map_get_string(upbx_sec, "secret") : NULL;
    if (secret) {
      nonce_set_secret(secret);
    } else {
      char auto_secret[33];
      for (int i = 0; i < 32; i++) {
        auto_secret[i] = "0123456789abcdef"[rand() % 16];
      }
      auto_secret[32] = '\0';
      nonce_set_secret(auto_secret);
      log_info("sip_udp: auto-generated secret (add 'secret = %s' to [upbx] section)", auto_secret);
    }

    const char *data_dir = upbx_sec ? resp_map_get_string(upbx_sec, "data_dir") : NULL;
    if (data_dir) {
      char *reg_dir = NULL;
      if (data_dir[0] == '/') {
        asprintf(&reg_dir, "%s/registrations", data_dir);
      } else {
        const char *config_path = config_get_path();
        char *config_dir = dirname(config_path ? strdup(config_path) : strdup("."));
        asprintf(&reg_dir, "%s/%s/registrations", config_dir, data_dir);
        free(config_dir);
      }
      registration_set_dir(reg_dir);
      free(reg_dir);
    }
    registration_init();
    call_init();
    group_config_init();

    if (addr_arr && addr_arr->type == RESPT_ARRAY && addr_arr->u.arr.n > 0) {
      int **fd_arrays = malloc(sizeof(int *) * addr_arr->u.arr.n);
      int valid_count = 0;

      for (size_t i = 0; i < addr_arr->u.arr.n; i++) {
        const char *addr = addr_arr->u.arr.elem[i].u.s;
        if (!addr || !addr[0]) {
          fd_arrays[i] = NULL;
          continue;
        }
        const char *clean_addr = addr;
        if (strncmp(clean_addr, "udp://", 6) == 0) {
          clean_addr = clean_addr + 6;
        }
        fd_arrays[i] = udp_recv(clean_addr, NULL, "5060");
        if (fd_arrays[i] && fd_arrays[i][0] > 0) {
          valid_count++;
          log_info("sip_udp: listening on %s", clean_addr);
        }
      }

      if (valid_count > 0) {
        sip_fds = merge_fd_arrays(fd_arrays, addr_arr->u.arr.n);
      } else {
        for (size_t i = 0; i < addr_arr->u.arr.n; i++) {
          free(fd_arrays[i]);
        }
        free(fd_arrays);
        log_error("sip_udp: failed to create sockets on any address");
        return SCHED_ERROR;
      }
      free(fd_arrays);
    } else {
      sip_fds = udp_recv(listen_str, NULL, "5060");
      if (!sip_fds || sip_fds[0] == 0) {
        log_error("sip_udp: failed to create socket on %s", listen_str);
        return SCHED_ERROR;
      }
      log_info("sip_udp: listening on %s", listen_str);
    }

    if (!sip_fds || sip_fds[0] == 0) {
      log_error("sip_udp: failed to create sockets");
      return SCHED_ERROR;
    }

    sip_transport_udp_set_fds(sip_fds);

    udata->state          = 1;
    udata->current_fd_idx = 1;
  }

  if (udata->state == 1 && sip_fds && sip_fds[0] > 0) {
    int ready_fd = sched_has_data(sip_fds);
    if (ready_fd >= 0) {
      udata->src_len = sizeof(udata->src_addr);
      ssize_t n      = recvfrom(ready_fd, udata->buf, sizeof(udata->buf) - 1, 0, (struct sockaddr *)&udata->src_addr,
                                &udata->src_len);

      if (n > 0) {
        udata->buf[n] = '\0';

        char src_ip[INET6_ADDRSTRLEN] = {0};
        int  src_port                 = 0;
        if (udata->src_addr.ss_family == AF_INET) {
          struct sockaddr_in *sin = (struct sockaddr_in *)&udata->src_addr;
          inet_ntop(AF_INET, &sin->sin_addr, src_ip, sizeof(src_ip));
          src_port = ntohs(sin->sin_port);
        } else if (udata->src_addr.ss_family == AF_INET6) {
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&udata->src_addr;
          inet_ntop(AF_INET6, &sin6->sin6_addr, src_ip, sizeof(src_ip));
          src_port = ntohs(sin6->sin6_port);
        }

        log_trace("sip_udp: received %zd bytes from %s:%d", n, src_ip, src_port);

        if (n == 4 && memcmp(udata->buf, "\r\n\r\n", 4) == 0) {
          log_trace("sip_udp: ignoring CRLF keepalive from %s:%d", src_ip, src_port);
          return SCHED_RUNNING;
        }

        if (sip_message_parse(udata->buf, (size_t)n, &udata->sip_msg) != 0) {
          log_warn("sip_udp: failed to parse SIP message from %s:%d", src_ip, src_port);
          log_hexdump_trace(udata->buf, (size_t)n);
          return SCHED_RUNNING;
        }

        log_hexdump_trace(udata->buf, (size_t)n);

        size_t resp_len = 0;
        char  *resp     = NULL;

        if (!sip_is_request(&udata->sip_msg)) {
          registration_t *reg = registration_find_by_addr((const struct sockaddr *)&udata->src_addr);
          resp = call_handle_response(&udata->sip_msg, &udata->src_addr, reg, ready_fd, &resp_len);
          sip_message_free(&udata->sip_msg);

          if (resp) {
            socklen_t dst_len =
                (udata->src_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            ssize_t sent = sendto(ready_fd, resp, resp_len, 0, (struct sockaddr *)&udata->src_addr, dst_len);
            if (sent > 0) {
              log_trace("sip_udp: sent %zd bytes response", sent);
            } else {
              log_error("sip_udp: sendto failed: %s", strerror(errno));
            }
            free(resp);
          }
          return SCHED_RUNNING;
        }

        // Extract pbx_addr from request-URI and update registration
        if (udata->sip_msg.uri && udata->sip_msg.uri_len > 0) {
          char pbx_host[256] = "";
          char pbx_port[32]  = "";

          sip_uri_extract_host_port(udata->sip_msg.uri, udata->sip_msg.uri_len, pbx_host, sizeof(pbx_host), pbx_port,
                                    sizeof(pbx_port));

          if (pbx_host[0]) {
            char pbx_addr_full[300];
            if (pbx_port[0] && strcmp(pbx_port, "5060") != 0) {
              snprintf(pbx_addr_full, sizeof(pbx_addr_full), "%s:%s", pbx_host, pbx_port);
            } else {
              snprintf(pbx_addr_full, sizeof(pbx_addr_full), "%s", pbx_host);
            }

            registration_t *reg = registration_find_by_addr((const struct sockaddr *)&udata->src_addr);
            if (reg && reg->number) {
              registration_update_pbx_addr(reg->number, pbx_addr_full);
            }
          }
        }

        resp = sip_dispatch(&udata->sip_msg, &udata->src_addr, ready_fd, &resp_len);

        sip_message_free(&udata->sip_msg);

        if (resp) {
          log_hexdump_trace(resp, resp_len);
          socklen_t dst_len =
              (udata->src_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
          ssize_t sent = sendto(ready_fd, resp, resp_len, 0, (struct sockaddr *)&udata->src_addr, dst_len);
          if (sent > 0) {
            log_trace("sip_udp: sent %zd bytes response", sent);
          } else {
            log_error("sip_udp: sendto failed: %s", strerror(errno));
          }
          free(resp);
        }
      }
    }
  }

  return SCHED_RUNNING;
}
