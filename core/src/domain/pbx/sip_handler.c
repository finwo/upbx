#include "domain/pbx/sip_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/digest_auth.h"
#include "common/hexdump.h"
#include "common/resp.h"
#include "common/socket_util.h"
#include "domain/pbx/call.h"
#include "domain/pbx/extension.h"
#include "domain/pbx/media_proxy.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/routing.h"
#include "domain/pbx/sip_builder.h"
#include "domain/pbx/sip_parser.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

#define EXPIRES_DEFAULT 60
#define EXPIRES_MAX     300

static const char *default_realm = "upbx.local";

static char *generate_branch_id(void) {
  static char branch[64];
  snprintf(branch, sizeof(branch), "z9hG4bK%08x%08x",
           (unsigned int)rand(), (unsigned int)time(NULL));
  return branch;
}

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
  // Skip leading whitespace
  while (*start == ' ' || *start == '\t') start++;
  // Skip quoted display name if present
  if (start[0] == '"') {
    const char *quote_end = strchr(start + 1, '"');
    if (quote_end) {
      start = quote_end + 1;
      while (*start == ' ' || *start == '\t') start++;
    }
  }
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
    char *resp = sip_build_message(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_extension_t *ext = pbx_extension_find(user);
  log_info("pbx: REGISTER extension lookup: user=%s found=%p", user, ext);
  if (!ext || !ext->secret) {
    log_warn("pbx: REGISTER - extension not found or no secret, returning 404");
    char *resp = sip_build_message(404, "Not Found", msg, NULL, NULL);
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

    char *resp = sip_build_message(401, "Unauthorized", msg, www_auth, NULL);
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
    char *resp = sip_build_message(403, "Forbidden", msg, NULL, NULL);
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

  char *host_port = sip_request_uri_host_port(msg);
  pbx_registration_create(user, contact, ctx->fd, (struct sockaddr *)&ctx->remote_addr, expires, host_port);
  free(host_port);

  char expires_header[64];
  snprintf(expires_header, sizeof(expires_header), "Expires: %d", expires);
  char *resp = sip_build_message(200, "OK", msg, expires_header, NULL);
  send_response(ctx, resp);
  free(resp);
  free(user);
}

static int count_media_streams(const char *sdp) {
  if (!sdp) return 0;
  int count = 0;
  const char *ptr = sdp;
  while (*ptr) {
    if (ptr[0] == 'm' && ptr[1] == '=') {
      count++;
    }
    ptr++;
  }
  return count;
}

static char *rewrite_sdp_for_proxy(const char *sdp, const char *advertise_ip, int *ports, int port_count, int *rtcp_ports, int rtcp_port_count) {
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
          char media[64] = {0};
          int port = 0;
          char rest[256] = {0};
          if (sscanf(buf, "%63s %d %255[^\n]", media, &port, rest) >= 2) {
            buf[0] = '\0';
            snprintf(buf, sizeof(buf), "%s %d %s", media, ports[port_idx], rest);
          }
        }
      } else if (line_len >= 2 && buf[0] == 'c' && buf[1] == '=') {
        buf[0] = '\0';
        snprintf(buf, sizeof(buf), "c=IN IP4 %s", advertise_ip && advertise_ip[0] ? advertise_ip : "");
      } else if (line_len >= 2 && buf[0] == 'o' && buf[1] == '=') {
        char username[128] = {0};
        char sess_id[128] = {0};
        char sess_version[128] = {0};
        char rest[256] = {0};
        if (sscanf(buf, "%127s %127s %127s %255[^\n]", username, sess_id, sess_version, rest) >= 3) {
          buf[0] = '\0';
          snprintf(buf, sizeof(buf), "%s %s %s IN IP4 %s", username, sess_id, sess_version, advertise_ip && advertise_ip[0] ? advertise_ip : "");
        }
      } else if (line_len >= 2 && buf[0] == 'a' && buf[1] == '=') {
        // Strip a=rtcp-mux and any existing a=rtcp: lines
        if (strncmp(buf, "a=rtcp-mux", 10) == 0 || strncmp(buf, "a=rtcp:", 7) == 0) {
          goto next_line;
        }
      }

      strcat(result, buf);
      strcat(result, "\r\n");

      // After m= line, inject a=rtcp:<port> for the corresponding RTCP socket
      if (line_len >= 2 && buf[0] == 'm' && buf[1] == '=') {
        if (port_idx < rtcp_port_count && rtcp_ports) {
          char rtcp_line[128];
          snprintf(rtcp_line, sizeof(rtcp_line), "a=rtcp:%d", rtcp_ports[port_idx]);
          strcat(result, rtcp_line);
          strcat(result, "\r\n");
        }
        port_idx++;
      }
    }

next_line:
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
    char *resp = sip_build_message(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  char *user = sip_request_uri_user(msg);
  if (!user) {
    log_warn("pbx: INVITE - no user in URI, returning 400");
    char *resp = sip_build_message(400, "Bad Request", msg, NULL, NULL);
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
    char *resp = sip_build_message(400, "Bad Request", msg, NULL, NULL);
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
    char *resp = sip_build_message(404, "Not Found", msg, NULL, NULL);
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
      char *resp = sip_build_message(403, "Forbidden", msg, NULL, NULL);
      send_response(ctx, resp);
      free(resp);
      free(user);
      free(source_ext);
      return;
    }

    if (dst_grp && !dst_grp->allow_incoming_cross_group) {
      char *resp = sip_build_message(403, "Forbidden", msg, NULL, NULL);
      send_response(ctx, resp);
      free(resp);
      free(user);
      free(source_ext);
      return;
    }
  }

  if (!msg->call_id) {
    char *resp = sip_build_message(400, "Bad Request", msg, NULL, NULL);
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
    char *resp = sip_build_message(500, "Server Internal Error", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    free(user);
    free(source_ext);
    return;
  }

  // Save the original Via from the caller for later use in responses
  pbx_call_set_via(msg->call_id, msg->via, NULL);

  log_debug("pbx: INVITE - creating media proxy session");
  if (pbx_media_proxy_session_create(msg->call_id) != 0) {
    log_error("pbx: INVITE - media proxy session create failed");
    char *resp = sip_build_message(503, "Service Unavailable", msg, NULL, NULL);
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

  int num_streams = count_media_streams(msg->body);
  if (num_streams < 1) num_streams = 1;
  if (num_streams > 16) num_streams = 16;

  int src_ports[16] = {0};
  int dst_ports[16] = {0};
  int src_rtcp_ports[16] = {0};
  int dst_rtcp_ports[16] = {0};
  char src_advertise_addr[16][64] = {0};
  char dst_advertise_addr[16][64] = {0};

  // Create RTP and RTCP sockets interleaved per stream:
  // src-rtp, src-rtcp, dst-rtp, dst-rtcp for each stream.
  // This ensures a non-compliant extension sending RTCP to rtp_port+1
  // hits the RTCP socket instead of another extension's media socket.
  for (int i = 0; i < num_streams; i++) {
    char src_socket_id[128], src_rtcp_id[128];
    char dst_socket_id[128], dst_rtcp_id[128];
    snprintf(src_socket_id, sizeof(src_socket_id), "%s-src-%d", msg->call_id, i);
    snprintf(src_rtcp_id, sizeof(src_rtcp_id), "%s-src-rtcp-%d", msg->call_id, i);
    snprintf(dst_socket_id, sizeof(dst_socket_id), "%s-dst-%d", msg->call_id, i);
    snprintf(dst_rtcp_id, sizeof(dst_rtcp_id), "%s-dst-rtcp-%d", msg->call_id, i);

    pbx_media_proxy_socket_info_t src_info = {0};
    pbx_media_proxy_socket_info_t src_rtcp_info = {0};
    pbx_media_proxy_socket_info_t dst_info = {0};
    pbx_media_proxy_socket_info_t dst_rtcp_info = {0};

    pbx_media_proxy_create_listen_socket(msg->call_id, src_socket_id, &src_info);
    pbx_media_proxy_create_listen_socket(msg->call_id, src_rtcp_id, &src_rtcp_info);
    pbx_media_proxy_create_listen_socket(msg->call_id, dst_socket_id, &dst_info);
    pbx_media_proxy_create_listen_socket(msg->call_id, dst_rtcp_id, &dst_rtcp_info);

    pbx_media_proxy_create_forward(msg->call_id, src_socket_id, dst_socket_id);
    pbx_media_proxy_create_forward(msg->call_id, dst_socket_id, src_socket_id);
    pbx_media_proxy_create_forward(msg->call_id, src_rtcp_id, dst_rtcp_id);
    pbx_media_proxy_create_forward(msg->call_id, dst_rtcp_id, src_rtcp_id);

    src_ports[i] = src_info.port;
    dst_ports[i] = dst_info.port;
    src_rtcp_ports[i] = src_rtcp_info.port;
    dst_rtcp_ports[i] = dst_rtcp_info.port;
    if (src_info.advertise_addr[0]) {
      strncpy(src_advertise_addr[i], src_info.advertise_addr, sizeof(src_advertise_addr[i]) - 1);
    }
    if (dst_info.advertise_addr[0]) {
      strncpy(dst_advertise_addr[i], dst_info.advertise_addr, sizeof(dst_advertise_addr[i]) - 1);
    }
  }

  const char *src_advertise = src_advertise_addr[0][0] ? src_advertise_addr[0] : (ctx->reg && ctx->reg->pbx_addr[0] ? ctx->reg->pbx_addr : NULL);
  const char *dst_advertise = dst_advertise_addr[0][0] ? dst_advertise_addr[0] : (dst_reg->pbx_addr[0] ? dst_reg->pbx_addr : NULL);

  pbx_call_set_media_info(msg->call_id, src_ports, num_streams, dst_ports, num_streams,
                          src_rtcp_ports, num_streams, dst_rtcp_ports, num_streams,
                          src_advertise, dst_advertise);

  const char *fwd_advertise_ip = dst_advertise ? dst_advertise : dst_reg->pbx_addr;
  const char *ring_advertise_ip = src_advertise ? src_advertise : (ctx->reg && ctx->reg->pbx_addr[0] ? ctx->reg->pbx_addr : NULL);

  log_debug("pbx: INVITE - msg->body=%p, num_streams=%d", (void*)msg->body, num_streams);
  log_debug("pbx: INVITE - src_ports[0]=%d, dst_ports[0]=%d, src_rtcp[0]=%d, dst_rtcp[0]=%d, fwd_advertise_ip=%s",
            src_ports[0], dst_ports[0], src_rtcp_ports[0], dst_rtcp_ports[0], fwd_advertise_ip ? fwd_advertise_ip : "null");

  char *ring_sdp = NULL;
  char *fwd_sdp = NULL;
  if (msg->body) {
    log_debug("pbx: INVITE - body len=%zu", strlen(msg->body));
    ring_sdp = rewrite_sdp_for_proxy(msg->body, ring_advertise_ip, src_ports, num_streams, src_rtcp_ports, num_streams);
    fwd_sdp = rewrite_sdp_for_proxy(msg->body, fwd_advertise_ip, dst_ports, num_streams, dst_rtcp_ports, num_streams);
    log_debug("pbx: INVITE - ring_sdp=%p, fwd_sdp=%p", (void*)ring_sdp, (void*)fwd_sdp);
    if (fwd_sdp) {
      log_debug("pbx: INVITE - fwd_sdp len=%zu, first line: %.50s", strlen(fwd_sdp), fwd_sdp);
    }
  }

  const char *src_pbx_addr = src_advertise ? src_advertise : (ctx->reg && ctx->reg->pbx_addr[0] ? ctx->reg->pbx_addr : fwd_advertise_ip);

  char contact[256];
  snprintf(contact, sizeof(contact), "sip:%s@%s:%d",
           dst_reg->extension, src_pbx_addr, dst_ports[0]);

  char extra_headers[512];
  snprintf(extra_headers, sizeof(extra_headers),
           "Contact: <%s>\r\n"
           "Content-Type: application/sdp", contact);

  char *resp2 = sip_build_message(180, "Ringing", msg, extra_headers, ring_sdp);
  send_response(ctx, resp2);
  free(resp2);
  free(ring_sdp);

  char new_uri[256];
  snprintf(new_uri, sizeof(new_uri), "sip:%s@%s", dst_reg->extension, dst_reg->pbx_addr[0] ? dst_reg->pbx_addr : src_pbx_addr);
  sip_rewrite_request_uri(msg, new_uri);

  char via_header[256];
  snprintf(via_header, sizeof(via_header), "SIP/2.0/UDP %s:5060;branch=%s;rport",
           dst_reg->pbx_addr[0] ? dst_reg->pbx_addr : src_pbx_addr,
           generate_branch_id());
  sip_replace_via(msg, via_header);

  // Save the Via we use for the destination for later use in responses
  pbx_call_set_via(msg->call_id, NULL, via_header);

  // Build Contact header - use destination's pbx_addr
  char forward_contact[256];
  snprintf(forward_contact, sizeof(forward_contact), "sip:%s@%s",
           dst_reg->extension, dst_reg->pbx_addr);

  char fwd_headers[512];
  snprintf(fwd_headers, sizeof(fwd_headers),
           "Contact: <%s>\r\n"
           "Content-Type: application/sdp", forward_contact);

  char *invite = sip_build_message(0, "INVITE", msg, fwd_headers, fwd_sdp);

  free(fwd_sdp);

  char dst_addr_str[128] = "";
  sockaddr_to_string((struct sockaddr *)&dst_reg->remote_addr, dst_addr_str, sizeof(dst_addr_str));
  log_debug("pbx: INVITE - forwarding to %s at %s (remote_addr=%s) dst_pbx_addr=%s",
            dst_reg->extension, dst_reg->contact, dst_addr_str, dst_reg->pbx_addr);
  log_hexdump_trace(invite, strlen(invite));

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

    char *other_ext = NULL;
    if (ctx->reg && strcmp(call->source_extension, ctx->reg->extension) == 0) {
      other_ext = call->destination_extension;
    } else if (ctx->reg) {
      other_ext = call->source_extension;
    }

    if (other_ext) {
      pbx_registration_t *other_reg = pbx_registration_find(other_ext);
      if (other_reg) {
        // Rewrite Request-URI for the other party
        char new_uri[256];
        char *other_pbx_addr = other_reg->pbx_addr[0] ? other_reg->pbx_addr : ctx->reg->pbx_addr;
        snprintf(new_uri, sizeof(new_uri), "sip:%s@%s", other_ext, other_pbx_addr);
        sip_rewrite_request_uri(msg, new_uri);

        // Add to-tag when forwarding to the destination (callee)
        if (strcmp(call->source_extension, ctx->reg->extension) == 0 && call->to_tag) {
          sip_update_to_tag(msg, call->to_tag);
        }

        // Build Contact header - use target's pbx_addr
        char contact_header[256];
        snprintf(contact_header, sizeof(contact_header), "sip:%s@%s",
                 ctx->reg->extension, other_reg->pbx_addr);
        char extra_hdrs[256];
        snprintf(extra_hdrs, sizeof(extra_hdrs), "Contact: <%s>", contact_header);

        char *ack = sip_build_message(0, "ACK", msg, extra_hdrs, NULL);
        char dst_addr_str[128] = "";
        sockaddr_to_string((struct sockaddr *)&other_reg->remote_addr, dst_addr_str, sizeof(dst_addr_str));
        log_debug("pbx: ACK - forwarding to %s at %s", other_ext, dst_addr_str);
        sendto(ctx->fd, ack, strlen(ack), 0,
               (struct sockaddr *)&other_reg->remote_addr, sizeof(other_reg->remote_addr));
        free(ack);
        free(other_reg);
      }
    }
  }
}

static void handle_bye(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;

  if (!ctx->reg) {
    log_warn("pbx: BYE - no valid registration, returning 403");
    char *resp = sip_build_message(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  if (!msg->call_id) {
    char *resp = sip_build_message(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_call_t *call = pbx_call_find(msg->call_id);
  if (!call) {
    char *resp = sip_build_message(481, "Call/Transaction Does Not Exist", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  char *other_ext = NULL;
  if (strcmp(call->source_extension, ctx->reg->extension) == 0) {
    other_ext = call->destination_extension;
  } else {
    other_ext = call->source_extension;
  }

  pbx_registration_t *other_reg = pbx_registration_find(other_ext);
  if (other_reg) {
    char new_uri[256];
    char *other_pbx_addr = other_reg->pbx_addr[0] ? other_reg->pbx_addr : ctx->reg->pbx_addr;
    snprintf(new_uri, sizeof(new_uri), "sip:%s@%s", other_ext, other_pbx_addr);
    sip_rewrite_request_uri(msg, new_uri);

    if (strcmp(call->source_extension, ctx->reg->extension) == 0 && call->to_tag) {
      sip_update_to_tag(msg, call->to_tag);
    }

    char via_header[256];
    snprintf(via_header, sizeof(via_header), "SIP/2.0/UDP %s:5060;branch=%s;rport",
             other_pbx_addr, generate_branch_id());
    sip_replace_via(msg, via_header);

    // Build Contact header - use target's pbx_addr
    char contact_header[256];
    snprintf(contact_header, sizeof(contact_header), "sip:%s@%s",
             ctx->reg->extension, other_pbx_addr);
    char extra_hdrs[256];
    snprintf(extra_hdrs, sizeof(extra_hdrs), "Contact: <%s>", contact_header);

    char *bye = sip_build_message(0, "BYE", msg, extra_hdrs, NULL);
    char dst_addr_str[128] = "";
    sockaddr_to_string((struct sockaddr *)&other_reg->remote_addr, dst_addr_str, sizeof(dst_addr_str));
    log_debug("pbx: BYE - forwarding to %s at %s", other_ext, dst_addr_str);
    sendto(ctx->fd, bye, strlen(bye), 0,
           (struct sockaddr *)&other_reg->remote_addr, sizeof(other_reg->remote_addr));
    free(bye);
    free(other_reg);
  }

  pbx_media_proxy_session_destroy(msg->call_id);
  pbx_call_delete(msg->call_id);

  char *resp = sip_build_message(200, "OK", msg, NULL, NULL);
  send_response(ctx, resp);
  free(resp);
}

static void handle_cancel(pbx_sip_context_t *ctx) {
  sip_message_t *msg = ctx->msg;

  if (!ctx->reg) {
    log_warn("pbx: CANCEL - no valid registration, returning 403");
    char *resp = sip_build_message(403, "Forbidden", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  if (!msg->call_id) {
    char *resp = sip_build_message(400, "Bad Request", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
    return;
  }

  pbx_call_t *call = pbx_call_find(msg->call_id);
  if (call) {
    char *other_ext = NULL;
    if (strcmp(call->source_extension, ctx->reg->extension) == 0) {
      other_ext = call->destination_extension;
    } else {
      other_ext = call->source_extension;
    }

    pbx_registration_t *other_reg = pbx_registration_find(other_ext);
    if (other_reg) {
      char new_uri[256];
      char *other_pbx_addr = other_reg->pbx_addr[0] ? other_reg->pbx_addr : ctx->reg->pbx_addr;
      snprintf(new_uri, sizeof(new_uri), "sip:%s@%s", other_ext, other_pbx_addr);
      sip_rewrite_request_uri(msg, new_uri);

      if (strcmp(call->source_extension, ctx->reg->extension) == 0 && call->to_tag) {
        sip_update_to_tag(msg, call->to_tag);
      }

      char via_header[256];
      snprintf(via_header, sizeof(via_header), "SIP/2.0/UDP %s:5060;branch=%s;rport",
               other_pbx_addr, generate_branch_id());
      sip_replace_via(msg, via_header);

      // Build Contact header - use target's pbx_addr
      char contact_header[256];
      snprintf(contact_header, sizeof(contact_header), "sip:%s@%s",
               ctx->reg->extension, other_pbx_addr);
      char extra_hdrs[256];
      snprintf(extra_hdrs, sizeof(extra_hdrs), "Contact: <%s>", contact_header);

      char *cancel = sip_build_message(0, "CANCEL", msg, extra_hdrs, NULL);
      char dst_addr_str[128] = "";
      sockaddr_to_string((struct sockaddr *)&other_reg->remote_addr, dst_addr_str, sizeof(dst_addr_str));
      log_debug("pbx: CANCEL - forwarding to %s at %s", other_ext, dst_addr_str);
      sendto(ctx->fd, cancel, strlen(cancel), 0,
             (struct sockaddr *)&other_reg->remote_addr, sizeof(other_reg->remote_addr));
      free(cancel);
      free(other_reg);
    }
  }

  char *resp = sip_build_message(487, "Request Terminated", msg, NULL, NULL);
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

  int status_code = sip_response_status_code(msg);
  if (status_code > 0) {
    log_debug("pbx: SIP response %d (call_id=%s)", status_code, msg->call_id ? msg->call_id : "(null)");
    if (msg->call_id && ctx->reg) {
      log_debug("pbx: response - ctx->reg->extension=%s", ctx->reg->extension);
      pbx_call_t *call = pbx_call_find(msg->call_id);
      if (call) {
        log_debug("pbx: response - call src=%s dst=%s", call->source_extension, call->destination_extension);

        char *other_ext = NULL;
        int *other_ports = NULL;
        int other_port_count = 0;
        int *other_rtcp_ports = NULL;
        int other_rtcp_port_count = 0;
        const char *other_advertise = NULL;
        if (strcmp(call->source_extension, ctx->reg->extension) == 0) {
          other_ext = call->destination_extension;
          other_ports = call->dest_media_ports;
          other_port_count = call->dest_media_port_count;
          other_rtcp_ports = call->dest_rtcp_ports;
          other_rtcp_port_count = call->dest_rtcp_port_count;
          other_advertise = call->dest_advertise;
        } else {
          other_ext = call->source_extension;
          other_ports = call->source_media_ports;
          other_port_count = call->source_media_port_count;
          other_rtcp_ports = call->source_rtcp_ports;
          other_rtcp_port_count = call->source_rtcp_port_count;
          other_advertise = call->source_advertise;
        }
        log_debug("pbx: response - other_ext=%s", other_ext);
        log_debug("pbx: response - msg->body=%p, other_ports=%p, other_port_count=%d, other_advertise=%s",
                  (void*)msg->body, (void*)other_ports, other_port_count, other_advertise ? other_advertise : "(null)");

        pbx_registration_t *other_reg = pbx_registration_find(other_ext);
        if (other_reg) {
          char *rewritten_sdp = NULL;
          if (msg->body && other_ports && other_port_count > 0 && other_advertise) {
            log_debug("pbx: response - rewriting SDP with c=%s ports=%d", other_advertise, other_port_count);
            rewritten_sdp = rewrite_sdp_for_proxy(msg->body, other_advertise, other_ports, other_port_count, other_rtcp_ports, other_rtcp_port_count);
          }

          // Restore the original Via from the party we're forwarding to
          const char *original_via = NULL;
          if (strcmp(call->source_extension, ctx->reg->extension) == 0) {
            // Response FROM source, forwarding TO destination, need destination's Via
            original_via = call->dest_via;
          } else {
            // Response FROM destination, forwarding TO source, need source's Via
            original_via = call->source_via;
          }
          if (original_via) {
            sip_replace_via(msg, original_via);
          } else {
            // Fallback: generate a new Via if no original is available
            char via_header[256];
            const char *pbx_addr = other_reg->pbx_addr[0] ? other_reg->pbx_addr :
                                    (ctx->reg && ctx->reg->pbx_addr[0] ? ctx->reg->pbx_addr : "127.0.0.1");
            snprintf(via_header, sizeof(via_header), "SIP/2.0/UDP %s:5060;branch=%s;rport",
                     pbx_addr, generate_branch_id());
            sip_replace_via(msg, via_header);
          }

          // Build Contact header for the response - use the target's pbx_addr
          char contact_header[256];
          char extra_hdrs[512];
          snprintf(contact_header, sizeof(contact_header), "sip:%s@%s",
                   ctx->reg->extension, other_reg->pbx_addr);
          if (rewritten_sdp || msg->body) {
            snprintf(extra_hdrs, sizeof(extra_hdrs),
                     "Contact: <%s>\r\nContent-Type: application/sdp", contact_header);
          } else {
            snprintf(extra_hdrs, sizeof(extra_hdrs),
                     "Contact: <%s>", contact_header);
          }

          char *response = sip_build_message(status_code, NULL, msg, extra_hdrs, rewritten_sdp ? rewritten_sdp : msg->body);
          free(rewritten_sdp);

          char dst_addr_str[128] = "";
          sockaddr_to_string((struct sockaddr *)&other_reg->remote_addr, dst_addr_str, sizeof(dst_addr_str));
          log_debug("pbx: forwarding response %d to %s at %s", status_code, other_ext, dst_addr_str);
          log_hexdump_trace(response, strlen(response));
          sendto(ctx->fd, response, strlen(response), 0,
                 (struct sockaddr *)&other_reg->remote_addr, sizeof(other_reg->remote_addr));
          free(response);
          free(other_reg);

          if (status_code == 200 && call->answered_at == 0) {
            pbx_call_set_answered(msg->call_id);
          }

          if (status_code == 200 && msg->to_tag && strcmp(call->destination_extension, ctx->reg->extension) == 0) {
            pbx_call_set_to_tag(msg->call_id, msg->to_tag);
          }
        }

        if (status_code == 481) {
          pbx_media_proxy_session_destroy(msg->call_id);
          pbx_call_delete(msg->call_id);
        }
      }
    }
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
    char *resp = sip_build_message(501, "Not Implemented", msg, NULL, NULL);
    send_response(ctx, resp);
    free(resp);
  }
}
