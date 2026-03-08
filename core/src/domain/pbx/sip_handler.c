#include "domain/pbx/sip_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/digest_auth.h"
#include "common/hexdump.h"
#include "common/resp.h"
#include "domain/pbx/call.h"
#include "domain/pbx/extension.h"
#include "domain/pbx/media_proxy.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/routing.h"
#include "domain/pbx/sip_builder.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

#define EXPIRES_DEFAULT 60
#define EXPIRES_MAX     300

static const char *default_realm = "upbx.local";

static const char *pbx_config_get_realm(void) {
  extern resp_object *domain_cfg;
  if (!domain_cfg) return default_realm;
  const char *val = resp_map_get_string(domain_cfg, "realm");
  return val ? val : default_realm;
}

static char *generate_nonce(void) {
  static char nonce[33];
  snprintf(nonce, sizeof(nonce), "%08x%08x%08x%08x",
           (unsigned int)rand(),
           (unsigned int)rand(),
           (unsigned int)rand(),
           (unsigned int)rand());
  return nonce;
}

static void send_response(pbx_sip_context_t *ctx, const char *response) {
  if (!response || !ctx) return;
  size_t len = strlen(response);
  sendto(ctx->fd, response, len, 0,
         (struct sockaddr *)&ctx->remote_addr, sizeof(ctx->remote_addr));
}

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

static void handle_register(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;
  char *user = sip_request_uri_user_from_to(msg);
  log_info("pbx: REGISTER user=%s uri=%s to=%s", user ? user : "(null)", msg->uri ? msg->uri : "(null)", msg->to ? msg->to : "(null)");
  if (!user) {
    log_warn("pbx: REGISTER - no user in URI, returning 400");
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_extension_t *ext = pbx_extension_find(user);
  log_info("pbx: REGISTER extension lookup: user=%s found=%p", user, ext);
  if (!ext || !ext->secret) {
    log_warn("pbx: REGISTER - extension not found or no secret, returning 404");
    char *resp = sip_build_response(404, "Not Found", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    return;
  }

  if (!msg->authorization) {
    log_info("pbx: REGISTER - no auth header, challenging with 401");
    char *www_auth = malloc(256);
    snprintf(www_auth, 256, "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\"", pbx_config_get_realm(), generate_nonce());

    log_info("pbx: REGISTER - %s", www_auth);

    char *resp = sip_build_response(401, "Unauthorized", msg, www_auth, NULL);
    log_info("pbx: REGISTER - response:\n%s", resp);
    send_response(ctx, resp);
    free(resp);
    free(www_auth);
    free(user);
    return;
  }

  log_info("pbx: REGISTER - authorization header: %s", msg->authorization);

  log_info("pbx: REGISTER - checking authorization");
  char *uri = sip_request_uri_host_port(msg);
  char *req_uri = sip_format_request_uri(user, uri ? uri : "localhost");
  free(uri);

  if (sip_security_check_raw(msg->authorization, msg->method, req_uri, ext->secret) != 0) {
    free(req_uri);
    log_warn("pbx: REGISTER - auth failed, returning 403");
    char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    return;
  }
  free(req_uri);

  log_info("pbx: REGISTER - auth success, creating registration");
  const char *contact = msg->contact;
  int expires = EXPIRES_DEFAULT;
  if (contact) {
    const char *exp_str = strstr(contact, "expires=");
    if (exp_str) {
      expires = atoi(exp_str + 8);
    }
  }

  if (expires > EXPIRES_MAX) {
    expires = EXPIRES_MAX;
  }

  pbx_registration_create(user, contact, ctx->fd, (struct sockaddr *)&ctx->remote_addr, expires);

  char expires_header[64];
  snprintf(expires_header, sizeof(expires_header), "Expires: %d", expires);
  char *resp = sip_build_response(200, "OK", msg, expires_header, NULL);
  send_response(ctx, resp);
  free(resp);
  free(user);
}

static char *rewrite_sdp_for_proxy(const char *sdp, const char *advertise_ip, int *ports, int port_count) {
  if (!sdp || !ports || port_count == 0) return NULL;
  
  char *result = malloc(4096);
  if (!result) return NULL;
  result[0] = '\0';
  
  char buf[512];
  const char *line_start = sdp;
  int port_idx = 0;
  
  while (line_start && *line_start) {
    const char *line_end = strchr(line_start, '\n');
    size_t line_len;
    if (line_end) {
      line_len = line_end - line_start;
    } else {
      line_len = strlen(line_start);
    }
    
    if (line_len > 1 && line_len < sizeof(buf)) {
      memcpy(buf, line_start, line_len);
      buf[line_len] = '\0';
      if (line_len > 0 && buf[line_len-1] == '\r') {
        buf[line_len-1] = '\0';
        line_len--;
      }
      
      if (line_len >= 2 && buf[0] == 'm' && buf[1] == '=') {
        if (port_idx < port_count) {
          char *port_start = buf + 2;
          while (*port_start == ' ') port_start++;
          char *port_end = strchr(port_start, ' ');
          if (port_end) {
            snprintf(buf, sizeof(buf), "m=%s %d %s", port_start, ports[port_idx], port_end + 1);
            port_idx++;
          }
        }
      } else if (line_len >= 2 && buf[0] == 'c' && buf[1] == '=') {
        snprintf(buf, sizeof(buf), "c=IN IP4 %s", advertise_ip && advertise_ip[0] ? advertise_ip : "");
      }
      
      strcat(result, buf);
      strcat(result, "\r\n");
    }
    
    if (line_end) {
      line_start = line_end + 1;
      if (*line_start == '\0') break;
    } else {
      break;
    }
  }
  
  return result;
}

static void handle_invite(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;

  log_debug("pbx: INVITE - ctx->reg=%p", ctx->reg);
  log_debug("pbx: INVITE - msg->uri=%s", msg->uri ? msg->uri : "(null)");
  log_debug("pbx: INVITE - msg->from=%s", msg->from ? msg->from : "(null)");
  log_debug("pbx: INVITE - msg->to=%s", msg->to ? msg->to : "(null)");

  if (!ctx->reg) {
    log_warn("pbx: INVITE - no valid registration, returning 403");
    char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  char *user = sip_request_uri_user(msg);
  if (!user) {
    log_warn("pbx: INVITE - no user in URI, returning 400");
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  log_debug("pbx: INVITE - user=%s", user);

  char *from = msg->from ? strdup(msg->from) : NULL;
  log_debug("pbx: INVITE - from=%s", from ? from : "(null)");
  char *source_ext = NULL;
  if (from) {
    if (strncmp(from, "sip:", 4) == 0) {
      source_ext = extract_extension_from_uri(from + 4);
    } else {
      source_ext = extract_extension_from_uri(from);
    }
    free(from);
  }

  log_debug("pbx: INVITE - source_ext=%s", source_ext ? source_ext : "(null)");

  if (!source_ext) {
    log_warn("pbx: INVITE - no source extension in From header, returning 400");
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    return;
  }

  pbx_extension_t *src_ext = pbx_extension_find(source_ext);
  log_debug("pbx: INVITE - src_ext=%p", src_ext);
  const char *source_group = src_ext ? src_ext->group_prefix : NULL;

  pbx_registration_t *dst_reg = pbx_route(source_ext, user, source_group);
  log_debug("pbx: INVITE - dst_reg=%p", dst_reg);
  if (!dst_reg) {
    char *resp = sip_build_response(404, "Not Found", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    free(source_ext);
    return;
  }

  pbx_extension_t *dst_ext = pbx_extension_find(dst_reg->extension);
  const char *dst_group = dst_ext ? dst_ext->group_prefix : NULL;

  if (source_group && dst_group && strcmp(source_group, dst_group) != 0) {
    pbx_group_t *src_grp = pbx_group_find(source_group);
    pbx_group_t *dst_grp = pbx_group_find(dst_group);

    if (src_grp && !src_grp->allow_outgoing_cross_group) {
      char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL);
      send_response(ctx, resp);
      free(resp);
      free(user);
      free(source_ext);
      return;
    }

    if (dst_grp && !dst_grp->allow_incoming_cross_group) {
      char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL);
      send_response(ctx, resp);
      free(resp);
      free(user);
      free(source_ext);
      return;
    }
  }

  if (!msg->call_id) {
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    free(source_ext);
    return;
  }

  pbx_call_t *call = pbx_call_create(msg->call_id, source_ext, dst_reg->extension, msg->from_tag);
  log_debug("pbx: INVITE - call=%p", call);
  (void)call;

  if (!call) {
    log_error("pbx: INVITE - failed to create call");
    char *resp = sip_build_response(500, "Server Internal Error", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    free(source_ext);
    return;
  }

  log_debug("pbx: INVITE - creating media proxy session");
  if (pbx_media_proxy_session_create(msg->call_id) != 0) {
    log_error("pbx: INVITE - media proxy session create failed");
    char *resp = sip_build_response(503, "Service Unavailable", msg, NULL, NULL);
    log_error("pbx: INVITE - built response");
    send_response(ctx, resp);
    log_error("pbx: INVITE - sent response");
    free(resp);
    log_error("pbx: INVITE - freeing call");
    log_error("pbx: INVITE - call_id=%s", msg->call_id ? msg->call_id : "(null)");
    pbx_call_delete(msg->call_id);
    log_error("pbx: INVITE - freeing user");
    free(user);
    log_error("pbx: INVITE - freeing source_ext");
    free(source_ext);
    log_error("pbx: INVITE - returning");
    return;
  }

  pbx_media_proxy_socket_info_t src_sock_info = {0};
  pbx_media_proxy_socket_info_t dst_sock_info = {0};

  char src_socket_id[32], dst_socket_id[32];
  snprintf(src_socket_id, sizeof(src_socket_id), "%s-src", msg->call_id);
  snprintf(dst_socket_id, sizeof(dst_socket_id), "%s-dst", msg->call_id);

  pbx_media_proxy_create_listen_socket(msg->call_id, src_socket_id, &src_sock_info);
  pbx_media_proxy_create_listen_socket(msg->call_id, dst_socket_id, &dst_sock_info);

  pbx_media_proxy_create_forward(msg->call_id, src_socket_id, dst_socket_id);
  pbx_media_proxy_create_forward(msg->call_id, dst_socket_id, src_socket_id);

  const char *advertise_ip = src_sock_info.advertise_addr[0] ? src_sock_info.advertise_addr : dst_reg->pbx_addr;
  
  int ports[16] = {0};
  ports[0] = src_sock_info.port;
  int port_count = 1;
  char *rewritten_sdp = NULL;
  if (msg->body) {
    rewritten_sdp = rewrite_sdp_for_proxy(msg->body, advertise_ip, ports, port_count);
  }
  
  char *sdp_to_use = rewritten_sdp;
  
  const char *src_pbx_addr = ctx->reg && ctx->reg->pbx_addr[0] ? ctx->reg->pbx_addr : advertise_ip;
  
  char contact[256];
  snprintf(contact, sizeof(contact), "sip:%s@%s:%d",
           dst_reg->extension, src_pbx_addr, dst_sock_info.port);
  
  char extra_headers[512];
  snprintf(extra_headers, sizeof(extra_headers),
           "Contact: <%s>\r\n"
           "Content-Type: application/sdp", contact);

  char *resp2 = sip_build_response(180, "Ringing", msg, extra_headers, sdp_to_use);
  send_response(ctx, resp2);
  free(resp2);
  free(rewritten_sdp);

  char new_uri[256];
  snprintf(new_uri, sizeof(new_uri), "sip:%s@%s", dst_reg->extension, dst_reg->pbx_addr[0] ? dst_reg->pbx_addr : src_pbx_addr);
  sip_rewrite_request_uri(msg, new_uri);

  char forward_contact[256];
  snprintf(forward_contact, sizeof(forward_contact), "sip:%s@%s:%d", dst_reg->extension, src_pbx_addr, dst_sock_info.port);
  
  char fwd_headers[512];
  snprintf(fwd_headers, sizeof(fwd_headers),
           "Contact: <%s>\r\n"
           "Content-Type: application/sdp", forward_contact);
  
  char *invite = sip_build_response(0, "INVITE", msg, fwd_headers, sdp_to_use);
  
  log_debug("pbx: INVITE - forwarding to %s at %s", dst_reg->extension, dst_reg->contact);
  
  sendto(ctx->fd, invite, strlen(invite), 0,
         (struct sockaddr *)&dst_reg->remote_addr, sizeof(dst_reg->remote_addr));
  free(invite);

  free(user);
  free(source_ext);
}

static void handle_ack(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;
  if (!msg->call_id) return;

  pbx_call_t *call = pbx_call_find(msg->call_id);
  if (call) {
    log_debug("pbx: ACK for call %s - media established", msg->call_id);
  }
}

static void handle_bye(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;

  if (!ctx->reg) {
    log_warn("pbx: BYE - no valid registration, returning 403");
    char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  if (!msg->call_id) {
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_call_t *call = pbx_call_find(msg->call_id);
  if (!call) {
    char *resp = sip_build_response(481, "Call/Transaction Does Not Exist", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_media_proxy_session_destroy(msg->call_id);
  pbx_call_delete(msg->call_id);

  char *resp = sip_build_response(200, "OK", msg, NULL, NULL);
  send_response(ctx, resp);
  free(resp);
}

static void handle_cancel(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;

  if (!ctx->reg) {
    log_warn("pbx: CANCEL - no valid registration, returning 403");
    char *resp = sip_build_response(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  if (!msg->call_id) {
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_call_t *call = pbx_call_find(msg->call_id);
  if (call) {
    pbx_media_proxy_session_destroy(msg->call_id);
    pbx_call_delete(msg->call_id);
  }

  char *resp = sip_build_response(487, "Request Terminated", msg, NULL, NULL);
  send_response(ctx, resp);
  free(resp);
}

void pbx_sip_handle(pbx_sip_context_t *ctx) {
  if (!ctx || !ctx->msg) return;

  sip_message_t *msg = ctx->msg;

  if (!msg->method) {
    log_warn("pbx: no method in SIP message");
    return;
  }

  log_debug("pbx: SIP %s", msg->method);

  if (strcmp(msg->method, "REGISTER") == 0) {
    handle_register(ctx);
  } else if (strcmp(msg->method, "INVITE") == 0) {
    handle_invite(ctx);
  } else if (strcmp(msg->method, "ACK") == 0) {
    handle_ack(ctx);
  } else if (strcmp(msg->method, "BYE") == 0) {
    handle_bye(ctx);
  } else if (strcmp(msg->method, "CANCEL") == 0) {
    handle_cancel(ctx);
  } else {
    char *resp = sip_build_response(501, "Not Implemented", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
  }
}
