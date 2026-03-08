#include "domain/pbx/sip_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/digest_auth.h"
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
  if (strncmp(uri, "sip:", 4) == 0) {
    const char *user = uri + 4;
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

static char *rewrite_sdp_for_proxy(char *sdp, const char *advertise_ip) {
  (void)sdp;
  (void)advertise_ip;
  return sdp;
}

static void handle_invite(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;

  char *user = sip_request_uri_user(msg);
  if (!user) {
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  char *from = sip_header_copy(msg, "From");
  char *source_ext = NULL;
  if (from) {
    if (strncmp(from, "sip:", 4) == 0) {
      source_ext = extract_extension_from_uri(from + 4);
    } else {
      source_ext = extract_extension_from_uri(from);
    }
    free(from);
  }

  if (!source_ext) {
    char *resp = sip_build_response(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    return;
  }

  pbx_extension_t *src_ext = pbx_extension_find(source_ext);
  const char *source_group = src_ext ? src_ext->group_prefix : NULL;

  pbx_registration_t *dst_reg = pbx_route(source_ext, user, source_group);
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
  (void)call;

  if (pbx_media_proxy_session_create(msg->call_id) != 0) {
    char *resp = sip_build_response(503, "Service Unavailable", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    pbx_call_delete(msg->call_id);
    free(user);
    free(source_ext);
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

  char sdp[512];
  snprintf(sdp, sizeof(sdp),
           "v=0\r\n"
           "o=- 0 0 IN IP4 %s\r\n"
           "s=Session\r\n"
           "c=IN IP4 %s\r\n"
           "t=0 0\r\n"
           "m=audio %d RTP/AVP 0\r\n"
           "a=rtpmap:0 PCMU/8000\r\n",
           src_sock_info.advertise_addr, src_sock_info.advertise_addr, src_sock_info.port);

  pbx_call_set_rtp_info(msg->call_id, msg->call_id, src_sock_info.port, dst_sock_info.port,
                         src_sock_info.advertise_addr, dst_sock_info.advertise_addr);

  char *new_uri = sip_format_request_uri(dst_reg->extension, "localhost");
  sip_rewrite_request_uri(msg, new_uri);
  free(new_uri);

  char *resp = sip_build_response(100, "Trying", msg, NULL, NULL);
  send_response(ctx, resp);
  free(resp);

  char contact[256];
  snprintf(contact, sizeof(contact), "sip:%s@%s:%d",
           dst_reg->extension, dst_sock_info.advertise_addr, dst_sock_info.port);

  char extra_headers[512];
  snprintf(extra_headers, sizeof(extra_headers),
           "Contact: <%s>\r\n"
           "Content-Type: application/sdp", contact);

  char *resp2 = sip_build_response(180, "Ringing", msg, extra_headers, sdp);
  send_response(ctx, resp2);
  free(resp2);

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
