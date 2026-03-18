#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include "command/command.h"
#include "common/scheduler.h"
#include "config/config.h"
#include "udphole/client.h"
#include "sip/parser.h"
#include "sip/message.h"
#include "sip/listener.h"
#include "pbx/extension.h"
#include "pbx/trunk.h"
#include "pbx/dialplan.h"
#include "sdp/sdp.h"
#include "rxi/log.h"

static volatile int g_running = 1;

static void signal_handler(int sig) {
  (void)sig;
  g_running = 0;
}

struct daemon_state {
  struct upbx_config *config;
  struct udphole_client *udphole;
  struct sip_listener *sip;
  struct pbx_extension_registry *extensions;
  struct pbx_trunk *trunks;
};

static int daemon_task(int64_t timestamp, struct pt_task *task) {
  struct daemon_state *state = task->udata;

  (void)timestamp;

  if (!g_running) {
    return SCHED_DONE;
  }

  pbx_extension_cleanup_expired(state->extensions);

  int *fds = state->sip->fds;
  int ready_fd = sched_has_data(fds);
  if (ready_fd <= 0) {
    return SCHED_RUNNING;
  }

  log_debug("daemon: got fd %d", ready_fd);

  char buf[8192];
  struct sockaddr_storage src;
  socklen_t src_len = sizeof(src);
  ssize_t n = recvfrom(ready_fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &src_len);
  if (n <= 0) {
    return SCHED_RUNNING;
  }

  buf[n] = '\0';
  log_debug("daemon: received %zd bytes: %.*s", n, (int)n, buf);
  log_debug("daemon: first bytes: %02x %02x %02x %02x", 
    (unsigned char)buf[0], (unsigned char)buf[1], 
    (unsigned char)buf[2], (unsigned char)buf[3]);

  struct sip_request *req = sip_parse_request(buf, n);
  if (!req) {
    log_debug("daemon: failed to parse SIP request");
    return SCHED_RUNNING;
  }

  log_debug("daemon: parsed SIP method_str=%s method=%d uri=%s", 
    req->method_str ? req->method_str : "(null)",
    req->method,
    req->uri ? req->uri : "(null)");

  switch (req->method) {
    case SIP_METHOD_REGISTER: {
      const char *uri_user = NULL;
      
      if (req->to) {
        const char *p = strstr(req->to, "sip:");
        if (!p) p = req->to;
        if (p) {
          p += 4;
          const char *end = strchr(p, '@');
          if (end) {
            uri_user = strndup(p, end - p);
          } else {
            end = strchr(p, '>');
            if (!end) end = p + strlen(p);
            uri_user = strndup(p, end - p);
          }
        }
      }

      struct upbx_extension *config_ext = NULL;
      if (uri_user) {
        log_debug("daemon: looking for extension %s (from To: %s)", uri_user, req->to);
        config_ext = upbx_config_find_extension(state->config, uri_user);
        log_debug("daemon: found config_ext=%p", (void*)config_ext);
      }

      if (!config_ext) {
        log_debug("daemon: extension not found, sending 404");
        char resp[] = "SIP/2.0 404 Not Found\r\n\r\n";
        sip_listener_send(state->sip, &src, resp, strlen(resp));
        free((char *)uri_user);
        sip_request_free(req);
        break;
      }

      int expires = 60;
      if (req->expires > 0) {
        expires = req->expires;
      }

      char response[1024];
      const char *auth_header = req->authorization ? req->authorization : req->proxy_authorization;
      int reg_result = pbx_extension_handle_register(
        state->extensions,
        config_ext,
        req->contact,
        expires,
        auth_header,
        &src,
        req->uri
      );

      char *nonce = pbx_extension_get_nonce(state->extensions, &src);

      log_debug("daemon: register result=%d", reg_result);

      if (reg_result == 401) {
        log_debug("daemon: sending 401 challenge, nonce=%s", nonce ? nonce : "(null)");
        log_debug("daemon: auth_header=%s", auth_header ? auth_header : "(null)");
        snprintf(response, sizeof(response),
            "SIP/2.0 401 Unauthorized\r\n"
            "Via: %s\r\n"
            "From: %s\r\n"
            "To: %s\r\n"
            "Call-ID: %s\r\n"
            "CSeq: %s\r\n"
            "WWW-Authenticate: Digest realm=\"upbx\", nonce=\"%s\", algorithm=MD5\r\n"
            "Content-Length: 0\r\n"
            "\r\n",
            req->via ? req->via : "",
            req->from ? req->from : "",
            req->to ? req->to : "",
            req->call_id ? req->call_id : "",
            req->cseq ? req->cseq : "",
            nonce ? nonce : ""
        );
      } else if (reg_result == 403) {
        snprintf(response, sizeof(response),
          "SIP/2.0 403 Forbidden\r\n"
          "Via: %s\r\n"
          "From: %s\r\n"
          "To: %s\r\n"
          "Call-ID: %s\r\n"
          "CSeq: %s\r\n"
          "Content-Length: 0\r\n"
          "\r\n",
          req->via ? req->via : "",
          req->from ? req->from : "",
          req->to ? req->to : "",
          req->call_id ? req->call_id : "",
          req->cseq ? req->cseq : ""
        );
      } else if (reg_result == 200) {
        snprintf(response, sizeof(response),
          "SIP/2.0 200 OK\r\n"
          "Via: %s\r\n"
          "From: %s\r\n"
          "To: %s\r\n"
          "Call-ID: %s\r\n"
          "CSeq: %s\r\n"
          "Expires: %d\r\n"
          "Content-Length: 0\r\n"
          "\r\n",
          req->via ? req->via : "",
          req->from ? req->from : "",
          req->to ? req->to : "",
          req->call_id ? req->call_id : "",
          req->cseq ? req->cseq : "",
          expires
        );
      }
      sip_listener_send(state->sip, &src, response, strlen(response));

      free((char *)uri_user);
      sip_request_free(req);
      break;
    }

    case SIP_METHOD_INVITE: {
      const char *uri_user = NULL;
      if (req->uri) {
        const char *p = strchr(req->uri, ':');
        if (p) {
          p++;
          const char *end = strchr(p, '@');
          if (end) {
            uri_user = strndup(p, end - p);
          } else {
            uri_user = strdup(p);
          }
        }
      }

      if (!uri_user) {
        char resp[] = "SIP/2.0 400 Bad Request\r\n\r\n";
        sip_listener_send(state->sip, &src, resp, strlen(resp));
        sip_request_free(req);
        break;
      }

      struct pbx_extension_entry *ext = pbx_extension_find_by_addr(state->extensions, &src);
      const char *caller_group = NULL;
      if (ext && ext->config_ext && ext->config_ext->group) {
        caller_group = ext->config_ext->group;
      }

      struct dialplan_result route_result = {0};
      int route_err = dialplan_route(state->config, caller_group, uri_user, &route_result);

      char response[1024];
      if (route_err < 0) {
        snprintf(response, sizeof(response),
          "SIP/2.0 404 Not Found\r\n"
          "Via: %s\r\n"
          "From: %s\r\n"
          "To: %s\r\n"
          "Call-ID: %s\r\n"
          "CSeq: %s\r\n"
          "Content-Length: 0\r\n"
          "\r\n",
          req->via ? req->via : "",
          req->from ? req->from : "",
          req->to ? req->to : "",
          req->call_id ? req->call_id : "",
          req->cseq ? req->cseq : ""
        );
        sip_listener_send(state->sip, &src, response, strlen(response));
        free((char *)uri_user);
        sip_request_free(req);
        break;
      }

      if (route_result.is_emergency) {
        snprintf(response, sizeof(response),
          "SIP/2.0 100 Trying\r\n"
          "Via: %s\r\n"
          "From: %s\r\n"
          "To: %s\r\n"
          "Call-ID: %s\r\n"
          "CSeq: %s\r\n"
          "Content-Length: 0\r\n"
          "\r\n",
          req->via ? req->via : "",
          req->from ? req->from : "",
          req->to ? req->to : "",
          req->call_id ? req->call_id : "",
          req->cseq ? req->cseq : ""
        );
        sip_listener_send(state->sip, &src, response, strlen(response));
      }

      if (!route_result.is_trunk) {
        snprintf(response, sizeof(response),
          "SIP/2.0 200 OK\r\n"
          "Via: %s\r\n"
          "From: %s\r\n"
          "To: %s\r\n"
          "Call-ID: %s\r\n"
          "CSeq: %s\r\n"
          "Content-Length: 0\r\n"
          "\r\n",
          req->via ? req->via : "",
          req->from ? req->from : "",
          req->to ? req->to : "",
          req->call_id ? req->call_id : "",
          req->cseq ? req->cseq : ""
        );
        sip_listener_send(state->sip, &src, response, strlen(response));
      } else {
        snprintf(response, sizeof(response),
          "SIP/2.0 100 Trying\r\n"
          "Via: %s\r\n"
          "From: %s\r\n"
          "To: %s\r\n"
          "Call-ID: %s\r\n"
          "CSeq: %s\r\n"
          "Content-Length: 0\r\n"
          "\r\n",
          req->via ? req->via : "",
          req->from ? req->from : "",
          req->to ? req->to : "",
          req->call_id ? req->call_id : "",
          req->cseq ? req->cseq : ""
        );
        sip_listener_send(state->sip, &src, response, strlen(response));
      }

      free((char *)uri_user);
      sip_request_free(req);
      break;
    }

    case SIP_METHOD_ACK:
    case SIP_METHOD_CANCEL:
    case SIP_METHOD_BYE:
    default:
      sip_request_free(req);
      break;
  }

  return SCHED_RUNNING;
}

static void print_usage(const char *prog) {
  fprintf(stderr, "Usage: %s daemon [options]\n", prog);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -c, --config <file>    Configuration file (default: /etc/upbx.conf or /etc/upbx/*.conf)\n");
  fprintf(stderr, "  -h, --help             Show this help\n");
}

static char *find_default_config(void) {
  struct stat st;
  
  if (stat("/etc/upbx", &st) == 0 && S_ISDIR(st.st_mode)) {
    return strdup("/etc/upbx");
  }
  
  if (stat("/etc/upbx.conf", &st) == 0) {
    return strdup("/etc/upbx.conf");
  }
  
  return NULL;
}

int cmd_daemon(int argc, const char **argv) {
  const char *config_path = NULL;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: -c requires a config file path\n");
        return 1;
      }
      config_path = argv[++i];
    } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      print_usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage(argv[0]);
      return 1;
    }
  }

  if (!config_path) {
    config_path = find_default_config();
  }

  if (!config_path) {
    fprintf(stderr, "Error: no config file specified and no default found at /etc/upbx or /etc/upbx.conf\n");
    print_usage(argv[0]);
    return 1;
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  struct upbx_config *config = upbx_config_load(config_path);
  if (!config) {
    fprintf(stderr, "daemon: failed to load config from %s\n", config_path);
    return 1;
  }

  struct sip_listener *sip = sip_listener_create(config);
  if (sip_listener_listen(sip, config->address) != 0) {
    fprintf(stderr, "daemon: failed to listen on %s\n", config->address);
    return 1;
  }

  struct pbx_extension_registry *extensions = pbx_extension_create(config);
  struct pbx_trunk *trunks = pbx_trunk_create(config);
  struct udphole_client *udphole = udphole_client_create(config);

  if (!udphole || udphole->fd < 0) {
    fprintf(stderr, "daemon: failed to connect to any rtpproxy\n");
    return 1;
  }

  struct daemon_state state = {
    .config = config,
    .udphole = udphole,
    .sip = sip,
    .extensions = extensions,
    .trunks = trunks,
  };

  sched_create(daemon_task, &state);

  printf("UPBX running. Press Ctrl+C to stop.\n");
  fflush(stdout);

  sched_main();

  if (udphole) udphole_client_destroy(udphole);
  if (sip) sip_listener_destroy(sip);
  if (extensions) pbx_extension_destroy(extensions);
  if (trunks) pbx_trunk_destroy(trunks);
  if (config) upbx_config_free(config);

  printf("UPBX stopped.\n");
  return 0;
}

void __attribute__((constructor)) cmd_daemon_setup(void) {
  struct cmd_struct *cmd = calloc(1, sizeof(struct cmd_struct));
  if (!cmd) {
    fprintf(stderr, "Failed to allocate memory for daemon command\n");
    return;
  }
  cmd->next = commands;
  cmd->fn = cmd_daemon;
  static const char *add_names[] = {"daemon", NULL};
  cmd->name = add_names;
  cmd->display = "daemon";
  cmd->description = "Run the main daemon";
  cmd->help_text = "";
  commands = cmd;
}
