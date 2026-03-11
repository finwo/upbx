#include "domain/pbx/trunk.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common/digest_auth.h"
#include "common/hexdump.h"
#include "common/resp.h"
#include "common/scheduler.h"
#include "common/socket_util.h"
#include "domain/config.h"
#include "domain/pbx/call.h"
#include "domain/pbx/media_proxy.h"
#include "domain/pbx/sip_builder.h"
#include "domain/pbx/sip_handler.h"
#include "domain/pbx/sip_parser.h"
#include "domain/pbx/transport_udp.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

#define TRUNK_EXPIRES_DEFAULT  300
#define TRUNK_BACKOFF_MAX      60
#define TRUNK_RESPONSE_TIMEOUT 5

/* ------------------------------------------------------------------ */
/* trunk registry: simple linked list                                  */
/* ------------------------------------------------------------------ */

typedef struct trunk_entry {
  struct trunk_entry *next;
  trunk_config_t      cfg;
  pt_task_t          *task; /* scheduler handle so we can remove it */
} trunk_entry_t;

static trunk_entry_t *trunk_list = NULL;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static int strcmp_null(const char *a, const char *b) {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  return strcmp(a, b);
}

static void trunk_config_free_fields(trunk_config_t *cfg) {
  if (!cfg) return;
  free(cfg->name);
  free(cfg->protocol);
  free(cfg->host);
  free(cfg->username);
  free(cfg->password);
  free(cfg->cid);
  for (size_t i = 0; i < cfg->did_count; i++) {
    free(cfg->dids[i]);
  }
  free(cfg->dids);
  for (size_t i = 0; i < cfg->group_count; i++) {
    free(cfg->groups[i]);
  }
  free(cfg->groups);
  for (size_t i = 0; i < cfg->rewrite_rule_count; i++) {
    free(cfg->rewrite_rules[i].pattern);
    free(cfg->rewrite_rules[i].replacement);
    regfree(&cfg->rewrite_rules[i].compiled);
  }
  free(cfg->rewrite_rules);
  memset(cfg, 0, sizeof(*cfg));
}

static void trunk_state_free(trunk_state_t *s) {
  if (!s) return;
  if (s->fd > 0) close(s->fd);
  free(s->nonce);
  free(s->realm);
  free(s);
}

static int trunk_resolve_remote(trunk_state_t *s) {
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", s->cfg->port);

  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  int rc = getaddrinfo(s->cfg->host, port_str, &hints, &res);
  if (rc != 0 || !res) {
    log_error("trunk[%s]: DNS resolution failed for %s:%s", s->cfg->name, s->cfg->host, port_str);
    return -1;
  }

  memcpy(&s->remote_addr, res->ai_addr, res->ai_addrlen);
  s->remote_addr_len = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}

static void trunk_generate_call_id(trunk_state_t *s) {
  snprintf(s->call_id, sizeof(s->call_id), "trunk-%s-%08x%08x", s->cfg->name, (unsigned int)rand(),
           (unsigned int)time(NULL));
}

/* ------------------------------------------------------------------ */
/* build and send REGISTER                                             */
/* ------------------------------------------------------------------ */

static void trunk_send_register(trunk_state_t *s) {
  s->cseq++;

  /* Build From / To : sip:username@host */
  char from_to[256];
  snprintf(from_to, sizeof(from_to), "<sip:%s@%s>;tag=trunk-%s", s->cfg->username ? s->cfg->username : "", s->cfg->host,
           s->cfg->name);

  char to_hdr[256];
  snprintf(to_hdr, sizeof(to_hdr), "<sip:%s@%s>", s->cfg->username ? s->cfg->username : "", s->cfg->host);

  /* Request-URI */
  char request_uri[256];
  snprintf(request_uri, sizeof(request_uri), "sip:%s:%d", s->cfg->host, s->cfg->port);

  /* Via */
  char via[256];
  snprintf(via, sizeof(via), "SIP/2.0/UDP 0.0.0.0:%d;branch=z9hG4bK%08x%08x;rport", s->local_port, (unsigned int)rand(),
           (unsigned int)time(NULL));

  /* Contact */
  char contact[256];
  snprintf(contact, sizeof(contact), "<sip:%s@0.0.0.0:%d>", s->cfg->username ? s->cfg->username : "", s->local_port);

  /* Build the base message using a fake sip_message_t template */
  sip_message_t tmpl;
  memset(&tmpl, 0, sizeof(tmpl));
  tmpl.method      = "REGISTER";
  tmpl.uri         = request_uri;
  tmpl.via         = via;
  tmpl.from        = from_to;
  tmpl.to          = to_hdr;
  tmpl.call_id     = s->call_id;
  tmpl.cseq        = s->cseq;
  tmpl.cseq_method = "REGISTER";

  /* Extra headers: Contact + Expires + optional Authorization */
  char extra[1024];
  int  extra_off = 0;

  extra_off +=
      snprintf(extra + extra_off, sizeof(extra) - extra_off,
               "Contact: %s\r\nExpires: %d\r\nUser-Agent: upbx-" UPBX_VERSION_STR, contact, TRUNK_EXPIRES_DEFAULT);

  if (s->auth_challenged && s->nonce && s->realm && s->cfg->username && s->cfg->password) {
    char *auth_uri = request_uri;

    HASHHEX ha1, ha2, response;
    digest_calc_ha1(s->cfg->username, s->realm, s->cfg->password, ha1);
    digest_calc_ha2("REGISTER", auth_uri, ha2);
    digest_calc_response(ha1, s->nonce, ha2, response);

    extra_off += snprintf(extra + extra_off, sizeof(extra) - extra_off,
                          "\r\nAuthorization: Digest username=\"%s\", realm=\"%s\", "
                          "nonce=\"%s\", uri=\"%s\", response=\"%s\"",
                          s->cfg->username, s->realm, s->nonce, auth_uri, response);
  }

  char *msg = sip_build_message(0, NULL, &tmpl, extra, NULL);
  if (!msg) {
    log_error("trunk[%s]: failed to build REGISTER", s->cfg->name);
    return;
  }

  ssize_t sent = sendto(s->fd, msg, strlen(msg), 0, (struct sockaddr *)&s->remote_addr, s->remote_addr_len);
  if (sent < 0) {
    log_error("trunk[%s]: sendto failed", s->cfg->name);
  } else {
    log_debug("trunk[%s]: sent REGISTER (cseq=%d, auth=%d)", s->cfg->name, s->cseq, s->auth_challenged);
  }

  free(msg);
}

/* ------------------------------------------------------------------ */
/* handle incoming response                                            */
/* ------------------------------------------------------------------ */

static char *parse_auth_param(const char *hdr, const char *param) {
  if (!hdr || !param) return NULL;
  const char *p = strstr(hdr, param);
  if (!p) return NULL;
  p += strlen(param);
  while (*p == ' ' || *p == '=' || *p == '"') p++;
  const char *end = p;
  while (*end && *end != '"' && *end != ',') end++;
  if (end <= p) return NULL;
  return strndup(p, (size_t)(end - p));
}

static void trunk_handle_call_response(trunk_state_t *s, sip_message_t *msg);

static void trunk_handle_response(trunk_state_t *s, time_t now) {
  sip_message_t *msg = sip_parse(s->recv_buf, strlen(s->recv_buf));
  if (!msg) return;

  /* If Call-ID doesn't match the registration transaction,
   * this is a call-related response (INVITE, BYE, etc.) */
  if (!msg->call_id || strcmp(msg->call_id, s->call_id) != 0) {
    trunk_handle_call_response(s, msg);
    sip_message_free(msg);
    return;
  }

  int status = sip_response_status_code(msg);

  if (status == 200) {
    /* Success - extract expires */
    int expires = TRUNK_EXPIRES_DEFAULT;
    if (msg->contact) {
      const char *exp_str = strstr(msg->contact, "expires=");
      if (exp_str) expires = atoi(exp_str + 8);
    }
    if (expires <= 0) expires = TRUNK_EXPIRES_DEFAULT;

    s->registered_at   = now;
    s->expires_seconds = expires;
    s->retry_count     = 0;
    s->auth_challenged = 0;

    /* Re-register at 80% of expiry */
    s->next_register = now + (time_t)(expires * 4 / 5);

    log_info("trunk[%s]: registered (expires=%d, next in %ds)", s->cfg->name, expires, (int)(s->next_register - now));

  } else if (status == 401) {
    /* Authentication challenge */
    const char *www_auth = msg->www_authenticate;
    if (www_auth) {
      free(s->realm);
      free(s->nonce);
      s->realm = parse_auth_param(www_auth, "realm");
      s->nonce = parse_auth_param(www_auth, "nonce");
    }

    if (s->auth_challenged) {
      /* Already tried auth and got 401 again - credentials are wrong */
      log_error("trunk[%s]: authentication failed (bad credentials?)", s->cfg->name);
      s->auth_challenged = 0;
      s->retry_count++;
      int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
      if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
      s->next_register = now + (time_t)backoff;
    } else {
      /* First challenge - retry immediately with auth */
      log_debug("trunk[%s]: received 401, retrying with auth", s->cfg->name);
      s->auth_challenged = 1;
      s->next_register   = now;
    }

  } else {
    /* Other error - backoff */
    log_warn("trunk[%s]: REGISTER returned %d", s->cfg->name, status);
    s->auth_challenged = 0;
    s->retry_count++;
    int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
    if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
    s->next_register = now + (time_t)backoff;
  }

  sip_message_free(msg);
}

/* ------------------------------------------------------------------ */
/* handle call-related responses (INVITE, BYE, etc.) from trunk        */
/* ------------------------------------------------------------------ */

static void trunk_handle_call_response(trunk_state_t *s, sip_message_t *msg) {
  if (!msg || !msg->call_id) return;

  int status = sip_response_status_code(msg);
  if (status <= 0) {
    /* In-dialog request from trunk (BYE, re-INVITE, etc.) */
    if (msg->method && strcmp(msg->method, "BYE") == 0) {
      pbx_call_t *call = pbx_call_find(msg->call_id);
      if (call && call->is_trunk_call) {
        log_info("trunk[%s]: BYE from trunk for call %s, forwarding to source '%s'", s->cfg->name, msg->call_id,
                 call->source_extension);

        /* Send 200 OK back to trunk via the trunk's dedicated fd */
        char *ok = sip_build_message(200, "OK", msg, NULL, NULL);
        if (ok) {
          sendto(s->fd, ok, strlen(ok), 0, (struct sockaddr *)&s->remote_addr, s->remote_addr_len);
          free(ok);
        }

        /* Forward BYE to source extension via the main SIP listener.
         * The extension's dialog expects:
         *   From: orig_to + trunk's tag (remote party = dialed number)
         *   To:   orig_from (local party = extension, already has extension's tag) */
        pbx_registration_t *src_reg = pbx_registration_find(call->source_extension);
        if (src_reg) {
          char from_with_tag[512];
          if (call->orig_to && call->to_tag) {
            char *tag_start = strstr(call->orig_to, ";tag=");
            if (tag_start) {
              size_t prefix_len = (size_t)(tag_start - call->orig_to);
              snprintf(from_with_tag, sizeof(from_with_tag), "%.*s;tag=%s", (int)prefix_len, call->orig_to,
                       call->to_tag);
            } else {
              snprintf(from_with_tag, sizeof(from_with_tag), "%s;tag=%s", call->orig_to, call->to_tag);
            }
          } else if (call->orig_to) {
            snprintf(from_with_tag, sizeof(from_with_tag), "%s", call->orig_to);
          } else {
            from_with_tag[0] = '\0';
          }

          sip_message_t fwd;
          memset(&fwd, 0, sizeof(fwd));
          fwd.method           = "BYE";
          const char *pbx_addr = call->source_advertise ? call->source_advertise : "127.0.0.1";
          char        uri[256];
          snprintf(uri, sizeof(uri), "sip:%s@%s:5060", call->source_extension, pbx_addr);
          fwd.uri         = uri;
          fwd.from        = from_with_tag;
          fwd.to          = call->orig_from;
          fwd.call_id     = msg->call_id;
          fwd.cseq        = call->orig_cseq + 1;
          fwd.cseq_method = "BYE";
          char via_hdr[256];
          snprintf(via_hdr, sizeof(via_hdr), "SIP/2.0/UDP %s:5060;branch=%s;rport", pbx_addr, "z9hG4bKtrunkbye");
          /* Generate proper branch */
          {
            char branch[64];
            snprintf(branch, sizeof(branch), "z9hG4bK%08x%08x", (unsigned int)rand(), (unsigned int)time(NULL));
            snprintf(via_hdr, sizeof(via_hdr), "SIP/2.0/UDP %s:5060;branch=%s;rport", pbx_addr, branch);
          }
          fwd.via = via_hdr;

          char *bye_msg = sip_build_message(0, NULL, &fwd, NULL, NULL);
          if (bye_msg) {
            log_debug("trunk[%s]: forwarding BYE to extension '%s'", s->cfg->name, call->source_extension);
            log_hexdump_trace(bye_msg, strlen(bye_msg));
            sendto(pbx_transport_get_sip_fd(), bye_msg, strlen(bye_msg), 0, (struct sockaddr *)&src_reg->remote_addr,
                   sizeof(src_reg->remote_addr));
            free(bye_msg);
          }
          free(src_reg);
        }

        pbx_media_proxy_session_destroy(msg->call_id);
        pbx_call_delete(msg->call_id);
        return;
      }
    }

    /* Respond to OPTIONS with 200 OK - required for trunk keepalive */
    if (msg->method && strcmp(msg->method, "OPTIONS") == 0) {
      log_debug("trunk[%s]: responding 200 OK to OPTIONS (call_id=%s)", s->cfg->name, msg->call_id);
      char *ok = sip_build_message(200, "OK", msg, "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS", NULL);
      if (ok) {
        sendto(s->fd, ok, strlen(ok), 0, (struct sockaddr *)&s->remote_addr, s->remote_addr_len);
        free(ok);
      }
      return;
    }

    log_debug("trunk[%s]: received in-dialog request (method=%s call_id=%s)", s->cfg->name,
              msg->method ? msg->method : "?", msg->call_id);
    return;
  }

  pbx_call_t *call = pbx_call_find(msg->call_id);
  if (!call || !call->is_trunk_call) {
    log_debug("trunk[%s]: response for unknown/non-trunk call %s", s->cfg->name, msg->call_id);
    return;
  }

  log_info("trunk[%s]: call response %d for call %s", s->cfg->name, status, msg->call_id);

  /* Find the source extension's registration to forward the response */
  pbx_registration_t *src_reg = pbx_registration_find(call->source_extension);
  if (!src_reg) {
    log_error("trunk[%s]: source extension '%s' no longer registered", s->cfg->name, call->source_extension);
    pbx_media_proxy_session_destroy(msg->call_id);
    pbx_call_delete(msg->call_id);
    return;
  }

  /* For responses forwarded to the source extension, we must reconstruct
   * the message in the extension's dialog context: use the extension's
   * original From, To, CSeq and Via -- not the trunk-facing ones. */

  /* Provisional responses (1xx): forward to source */
  if (status >= 100 && status < 200) {
    /* Rewrite SDP for source side if present */
    char *rewritten_sdp = NULL;
    if (msg->body && call->source_media_ports && call->source_media_port_count > 0 && call->source_advertise) {
      rewritten_sdp = pbx_rewrite_sdp_for_proxy(msg->body, call->source_advertise, call->source_media_ports,
                                                call->source_media_port_count, call->source_rtcp_ports,
                                                call->source_rtcp_port_count);
    }

    /* Build response in extension's dialog context */
    sip_message_t fwd;
    memset(&fwd, 0, sizeof(fwd));
    fwd.via         = call->source_via;
    fwd.from        = call->orig_from;
    fwd.to          = call->orig_to;
    fwd.call_id     = msg->call_id;
    fwd.cseq        = call->orig_cseq;
    fwd.cseq_method = call->orig_cseq_method;

    char extra_hdrs[512];
    if (rewritten_sdp || msg->body) {
      snprintf(extra_hdrs, sizeof(extra_hdrs), "Content-Type: application/sdp");
    } else {
      extra_hdrs[0] = '\0';
    }

    char *response = sip_build_message(status, NULL, &fwd, extra_hdrs[0] ? extra_hdrs : NULL,
                                       rewritten_sdp ? rewritten_sdp : msg->body);
    free(rewritten_sdp);

    if (response) {
      sendto(pbx_transport_get_sip_fd(), response, strlen(response), 0, (struct sockaddr *)&src_reg->remote_addr,
             sizeof(src_reg->remote_addr));
      free(response);
    }
    free(src_reg);
    return;
  }

  /* 2xx success: call answered */
  if (status >= 200 && status < 300) {
    /* Rewrite SDP from trunk for source extension side */
    char *rewritten_sdp = NULL;
    if (msg->body && call->source_media_ports && call->source_media_port_count > 0 && call->source_advertise) {
      rewritten_sdp = pbx_rewrite_sdp_for_proxy(msg->body, call->source_advertise, call->source_media_ports,
                                                call->source_media_port_count, call->source_rtcp_ports,
                                                call->source_rtcp_port_count);
    }

    /* Parse SDP from trunk to extract the trunk's media IP and port,
     * then create connect-mode sockets in the media proxy so we actively
     * send RTP to the trunk rather than waiting for the trunk to send first. */
    if (msg->body && call->dest_media_port_count > 0) {
      char trunk_media_ip[64] = {0};
      int  trunk_media_port   = 0;
      int  trunk_rtcp_port    = 0;

      /* Parse c= line for connection IP */
      const char *cline = strstr(msg->body, "c=IN IP4 ");
      if (cline) {
        cline += 9; /* skip "c=IN IP4 " */
        const char *end = cline;
        while (*end && *end != '\r' && *end != '\n' && *end != ' ') end++;
        size_t ip_len = (size_t)(end - cline);
        if (ip_len > 0 && ip_len < sizeof(trunk_media_ip)) {
          memcpy(trunk_media_ip, cline, ip_len);
          trunk_media_ip[ip_len] = '\0';
        }
      }

      /* Parse m=audio line for port */
      const char *mline = strstr(msg->body, "m=audio ");
      if (mline) {
        mline += 8; /* skip "m=audio " */
        trunk_media_port = atoi(mline);
      }

      /* Parse a=rtcp: line for RTCP port, default to RTP+1 */
      const char *rtcp_line = strstr(msg->body, "a=rtcp:");
      if (rtcp_line) {
        rtcp_line += 7;
        trunk_rtcp_port = atoi(rtcp_line);
      } else {
        trunk_rtcp_port = trunk_media_port + 1;
      }

      if (trunk_media_ip[0] && trunk_media_port > 0) {
        log_info("trunk[%s]: SDP answer media=%s:%d rtcp=%d, creating connect sockets", s->cfg->name, trunk_media_ip,
                 trunk_media_port, trunk_rtcp_port);

        for (int i = 0; i < call->dest_media_port_count; i++) {
          char dst_conn_id[128], dst_rtcp_conn_id[128];
          char src_socket_id[128], src_rtcp_id[128];
          char dst_listen_id[128], dst_rtcp_listen_id[128];

          snprintf(dst_conn_id, sizeof(dst_conn_id), "%s-dst-conn-%d", msg->call_id, i);
          snprintf(dst_rtcp_conn_id, sizeof(dst_rtcp_conn_id), "%s-dst-rtcp-conn-%d", msg->call_id, i);
          snprintf(src_socket_id, sizeof(src_socket_id), "%s-src-%d", msg->call_id, i);
          snprintf(src_rtcp_id, sizeof(src_rtcp_id), "%s-src-rtcp-%d", msg->call_id, i);
          snprintf(dst_listen_id, sizeof(dst_listen_id), "%s-dst-%d", msg->call_id, i);
          snprintf(dst_rtcp_listen_id, sizeof(dst_rtcp_listen_id), "%s-dst-rtcp-%d", msg->call_id, i);

          /* Create connect-mode sockets targeting the trunk's media address */
          if (pbx_media_proxy_create_connect_socket(msg->call_id, dst_conn_id, trunk_media_ip, trunk_media_port) == 0) {
            log_debug("trunk[%s]: created RTP connect socket %s -> %s:%d", s->cfg->name, dst_conn_id, trunk_media_ip,
                      trunk_media_port);
            /* Rewire: source listen -> new dst connect (outbound to trunk) */
            pbx_media_proxy_create_forward(msg->call_id, src_socket_id, dst_conn_id);
            /* Rewire: new dst connect -> source listen (inbound from trunk) */
            pbx_media_proxy_create_forward(msg->call_id, dst_conn_id, src_socket_id);
          }

          if (pbx_media_proxy_create_connect_socket(msg->call_id, dst_rtcp_conn_id, trunk_media_ip, trunk_rtcp_port) ==
              0) {
            log_debug("trunk[%s]: created RTCP connect socket %s -> %s:%d", s->cfg->name, dst_rtcp_conn_id,
                      trunk_media_ip, trunk_rtcp_port);
            pbx_media_proxy_create_forward(msg->call_id, src_rtcp_id, dst_rtcp_conn_id);
            pbx_media_proxy_create_forward(msg->call_id, dst_rtcp_conn_id, src_rtcp_id);
          }
        }
      }
    }

    /* Save to-tag from trunk (for forwarding ACK/BYE to trunk later) */
    if (msg->to_tag) {
      pbx_call_set_to_tag(msg->call_id, msg->to_tag);
    }

    /* Save Contact URI from trunk's 200 OK.
     * Per RFC 3261 §13.2.2.4, ACK for 2xx must target this URI. */
    if (msg->contact) {
      free(call->trunk_remote_contact);
      /* Extract URI from Contact header: strip < > if present */
      const char *c = msg->contact;
      while (*c == ' ') c++;
      if (*c == '<') {
        c++;
        const char *end = strchr(c, '>');
        if (end) {
          call->trunk_remote_contact = strndup(c, (size_t)(end - c));
        } else {
          call->trunk_remote_contact = strdup(c);
        }
      } else {
        call->trunk_remote_contact = strdup(c);
      }
      log_debug("trunk[%s]: saved remote contact URI: %s", s->cfg->name, call->trunk_remote_contact);
    }

    pbx_call_set_answered(msg->call_id);

    /* Build a To header with the trunk's to-tag appended to the extension's original To.
     * The extension needs a to-tag to form its dialog state. */
    char to_with_tag[512];
    if (call->orig_to && msg->to_tag) {
      /* Strip any existing tag from orig_to before appending the trunk's tag */
      char *tag_start = strstr(call->orig_to, ";tag=");
      if (tag_start) {
        size_t prefix_len = (size_t)(tag_start - call->orig_to);
        snprintf(to_with_tag, sizeof(to_with_tag), "%.*s;tag=%s", (int)prefix_len, call->orig_to, msg->to_tag);
      } else {
        snprintf(to_with_tag, sizeof(to_with_tag), "%s;tag=%s", call->orig_to, msg->to_tag);
      }
    } else if (call->orig_to) {
      snprintf(to_with_tag, sizeof(to_with_tag), "%s", call->orig_to);
    } else {
      to_with_tag[0] = '\0';
    }

    /* Build response in extension's dialog context */
    sip_message_t fwd;
    memset(&fwd, 0, sizeof(fwd));
    fwd.via         = call->source_via;
    fwd.from        = call->orig_from;
    fwd.to          = to_with_tag;
    fwd.call_id     = msg->call_id;
    fwd.cseq        = call->orig_cseq;
    fwd.cseq_method = call->orig_cseq_method;

    /* Build Contact pointing to the PBX so the extension sends ACK here */
    char        contact_hdr[256];
    const char *pbx_addr = call->source_advertise ? call->source_advertise : "127.0.0.1";
    snprintf(contact_hdr, sizeof(contact_hdr), "<sip:%s@%s:5060>", call->destination_extension, pbx_addr);

    char extra_hdrs[512];
    if (rewritten_sdp || msg->body) {
      snprintf(extra_hdrs, sizeof(extra_hdrs), "Contact: %s\r\nContent-Type: application/sdp", contact_hdr);
    } else {
      snprintf(extra_hdrs, sizeof(extra_hdrs), "Contact: %s", contact_hdr);
    }

    char *response = sip_build_message(status, NULL, &fwd, extra_hdrs, rewritten_sdp ? rewritten_sdp : msg->body);
    free(rewritten_sdp);

    if (response) {
      log_info("trunk[%s]: forwarding %d to source '%s'", s->cfg->name, status, call->source_extension);
      log_hexdump_trace(response, strlen(response));
      sendto(pbx_transport_get_sip_fd(), response, strlen(response), 0, (struct sockaddr *)&src_reg->remote_addr,
             sizeof(src_reg->remote_addr));
      free(response);
    }
    free(src_reg);
    return;
  }

  /* 401 Unauthorized: handle challenge-response auth */
  if (status == 401 && !call->trunk_auth_attempted) {
    const char *www_auth = msg->www_authenticate;
    if (www_auth && s->cfg->username && s->cfg->password) {
      char *challenge_realm = parse_auth_param(www_auth, "realm");
      char *challenge_nonce = parse_auth_param(www_auth, "nonce");

      if (challenge_realm && challenge_nonce) {
        log_info("trunk[%s]: 401 challenge for call %s, retrying with auth (realm=%s)", s->cfg->name, msg->call_id,
                 challenge_realm);

        call->trunk_auth_attempted = 1;

        /* Increment CSeq for the new INVITE */
        s->cseq++;

        /* Build the authenticated INVITE */
        char request_uri[256];
        snprintf(request_uri, sizeof(request_uri), "sip:%s@%s:%d", call->destination_extension, s->cfg->host,
                 s->cfg->port);

        /* Compute digest response */
        HASHHEX ha1, ha2, auth_response;
        digest_calc_ha1(s->cfg->username, challenge_realm, s->cfg->password, ha1);
        digest_calc_ha2("INVITE", request_uri, ha2);
        digest_calc_response(ha1, challenge_nonce, ha2, auth_response);

        /* Build From/To headers - use CID if configured, else source extension */
        const char *from_user = (s->cfg->cid && s->cfg->cid[0]) ? s->cfg->cid : call->source_extension;

        char from_hdr[256];
        snprintf(from_hdr, sizeof(from_hdr), "<sip:%s@%s:%d>;tag=%s", from_user, s->cfg->host, s->cfg->port,
                 call->from_tag ? call->from_tag : "upbx");

        char to_hdr[256];
        snprintf(to_hdr, sizeof(to_hdr), "<sip:%s@%s:%d>", call->destination_extension, s->cfg->host, s->cfg->port);

        /* New branch for the new transaction */
        char        via_hdr[256];
        const char *via_addr = call->dest_advertise ? call->dest_advertise : "0.0.0.0";
        {
          char branch[64];
          snprintf(branch, sizeof(branch), "z9hG4bK%08x%08x", (unsigned int)rand(), (unsigned int)time(NULL));
          snprintf(via_hdr, sizeof(via_hdr), "SIP/2.0/UDP %s:%d;branch=%s;rport", via_addr, s->local_port, branch);
        }

        pbx_call_set_via(msg->call_id, NULL, via_hdr);

        /* Contact header - must match From user for trunk to accept ACK */
        char contact_hdr[256];
        snprintf(contact_hdr, sizeof(contact_hdr), "<sip:%s@%s:%d>", from_user, via_addr, s->local_port);

        sip_message_t tmpl;
        memset(&tmpl, 0, sizeof(tmpl));
        tmpl.method      = "INVITE";
        tmpl.uri         = request_uri;
        tmpl.via         = via_hdr;
        tmpl.from        = from_hdr;
        tmpl.to          = to_hdr;
        tmpl.call_id     = msg->call_id;
        tmpl.cseq        = s->cseq;
        tmpl.cseq_method = "INVITE";

        /* Update trunk-side dialog headers for ACK/BYE reconstruction */
        free(call->trunk_from);
        call->trunk_from = strdup(from_hdr);
        free(call->trunk_to);
        call->trunk_to   = strdup(to_hdr);
        call->trunk_cseq = s->cseq;

        /* Build SDP: rewrite original source SDP with trunk-facing proxy ports */
        char *fwd_sdp = NULL;
        if (call->dest_media_ports && call->dest_media_port_count > 0 && call->dest_advertise) {
          char sdp_buf[1024];
          snprintf(sdp_buf, sizeof(sdp_buf),
                   "v=0\r\n"
                   "o=upbx 0 0 IN IP4 %s\r\n"
                   "s=call\r\n"
                   "c=IN IP4 %s\r\n"
                   "t=0 0\r\n"
                   "m=audio %d RTP/AVP 0 8 101\r\n"
                   "a=rtpmap:0 PCMU/8000\r\n"
                   "a=rtpmap:8 PCMA/8000\r\n"
                   "a=rtpmap:101 telephone-event/8000\r\n",
                   call->dest_advertise, call->dest_advertise, call->dest_media_ports[0]);
          fwd_sdp = strdup(sdp_buf);
        }

        char extra[1024];
        snprintf(extra, sizeof(extra),
                 "Contact: %s\r\n"
                 "Content-Type: application/sdp\r\n"
                 "Max-Forwards: 70\r\n"
                 "Authorization: Digest username=\"%s\", realm=\"%s\", "
                 "nonce=\"%s\", uri=\"%s\", response=\"%s\"",
                 contact_hdr, s->cfg->username, challenge_realm, challenge_nonce, request_uri, auth_response);

        char *invite = sip_build_message(0, NULL, &tmpl, extra, fwd_sdp);
        free(fwd_sdp);

        if (invite && s->fd > 0) {
          ssize_t sent =
              sendto(s->fd, invite, strlen(invite), 0, (struct sockaddr *)&s->remote_addr, s->remote_addr_len);
          if (sent > 0) {
            log_info("trunk[%s]: re-sent INVITE with auth (%zd bytes, CSeq=%d)", s->cfg->name, sent, s->cseq);
            log_hexdump_trace(invite, strlen(invite));
          } else {
            log_error("trunk[%s]: sendto failed for auth retry", s->cfg->name);
          }
          free(invite);
        } else {
          free(invite);
        }

        free(challenge_realm);
        free(challenge_nonce);
        free(src_reg);
        return;
      }

      free(challenge_realm);
      free(challenge_nonce);
    }
    /* If we couldn't parse the challenge or have no credentials, fall through to failover */
    log_warn("trunk[%s]: 401 but unable to authenticate (no credentials or bad challenge)", s->cfg->name);
  }

  /* 4xx/5xx/6xx failure: attempt failover to next trunk */
  log_warn("trunk[%s]: call %s failed with %d, attempting failover", s->cfg->name, msg->call_id, status);

  const char *source_group    = call->trunk_source_group;
  const char *original_dialed = call->trunk_original_dialed;
  int         next_index      = call->trunk_current_index + 1;

  if (!source_group || !original_dialed) {
    /* Can't failover without original info */
    char *resp503 = sip_build_message(503, "Service Unavailable", msg, NULL, NULL);
    if (call->source_via) sip_replace_via(msg, call->source_via);
    if (resp503) {
      sendto(pbx_transport_get_sip_fd(), resp503, strlen(resp503), 0, (struct sockaddr *)&src_reg->remote_addr,
             sizeof(src_reg->remote_addr));
      free(resp503);
    }
    pbx_media_proxy_session_destroy(msg->call_id);
    pbx_call_delete(msg->call_id);
    free(src_reg);
    return;
  }

  /* Get trunk list again and try from next_index */
  trunk_config_t *cfgs[16];
  trunk_state_t  *tstates[16];
  size_t          trunk_count = pbx_trunk_get_by_group(source_group, cfgs, tstates, 16);

  int found_next = 0;
  for (size_t t = (size_t)next_index; t < trunk_count; t++) {
    trunk_config_t *tcfg = cfgs[t];
    trunk_state_t  *tst  = tstates[t];

    if (!pbx_trunk_is_registered(tst)) {
      log_debug("trunk failover: trunk '%s' not registered, skipping", tcfg->name);
      continue;
    }

    /* Apply rewrite from original dialed number */
    char *rewritten = pbx_trunk_apply_rewrite(tcfg, original_dialed);
    log_info("trunk failover: trying trunk '%s', number '%s' -> '%s'", tcfg->name, original_dialed, rewritten);

    /* Update call record for new trunk */
    free(call->trunk_name);
    call->trunk_name          = strdup(tcfg->name);
    call->trunk_current_index = (int)t;
    free(call->destination_extension);
    call->destination_extension = strdup(rewritten);

    /* Build new INVITE */
    char *fwd_sdp = NULL;
    /* Re-read media info from call for trunk-facing SDP */
    if (call->dest_media_ports && call->dest_media_port_count > 0 && call->dest_advertise) {
      /* Build a minimal SDP for the new trunk */
      /* We need to construct a basic SDP since we don't have the original body stored.
       * For failover we use a simple offer. */
      char sdp_buf[1024];
      snprintf(sdp_buf, sizeof(sdp_buf),
               "v=0\r\n"
               "o=upbx 0 0 IN IP4 %s\r\n"
               "s=call\r\n"
               "c=IN IP4 %s\r\n"
               "t=0 0\r\n"
               "m=audio %d RTP/AVP 0 8 101\r\n"
               "a=rtpmap:0 PCMU/8000\r\n"
               "a=rtpmap:8 PCMA/8000\r\n"
               "a=rtpmap:101 telephone-event/8000\r\n",
               call->dest_advertise, call->dest_advertise, call->dest_media_ports[0]);
      fwd_sdp = strdup(sdp_buf);
    }

    /* Determine From user - use CID if configured, else source extension */
    const char *from_user = (tcfg->cid && tcfg->cid[0]) ? tcfg->cid : call->source_extension;

    char from_hdr[256];
    snprintf(from_hdr, sizeof(from_hdr), "<sip:%s@%s:%d>;tag=%s", from_user, tcfg->host, tcfg->port,
             call->from_tag ? call->from_tag : "upbx");

    char to_hdr[256];
    snprintf(to_hdr, sizeof(to_hdr), "<sip:%s@%s:%d>", rewritten, tcfg->host, tcfg->port);

    char request_uri[256];
    snprintf(request_uri, sizeof(request_uri), "sip:%s@%s:%d", rewritten, tcfg->host, tcfg->port);

    char        via_hdr[256];
    const char *via_addr = call->dest_advertise ? call->dest_advertise : "0.0.0.0";

    /* Generate proper branch */
    {
      char branch[64];
      snprintf(branch, sizeof(branch), "z9hG4bK%08x%08x", (unsigned int)rand(), (unsigned int)time(NULL));
      snprintf(via_hdr, sizeof(via_hdr), "SIP/2.0/UDP %s:%d;branch=%s;rport", via_addr, tst->local_port, branch);
    }

    pbx_call_set_via(msg->call_id, NULL, via_hdr);

    sip_message_t tmpl;
    memset(&tmpl, 0, sizeof(tmpl));
    tmpl.method  = "INVITE";
    tmpl.uri     = request_uri;
    tmpl.via     = via_hdr;
    tmpl.from    = from_hdr;
    tmpl.to      = to_hdr;
    tmpl.call_id = msg->call_id;
    tst->cseq++;
    tmpl.cseq        = tst->cseq;
    tmpl.cseq_method = "INVITE";

    /* Contact header - must match From user for trunk to accept ACK */
    char contact_hdr[256];
    snprintf(contact_hdr, sizeof(contact_hdr), "<sip:%s@%s:%d>", from_user, via_addr, tst->local_port);

    char extra[512];
    snprintf(extra, sizeof(extra),
             "Contact: %s\r\n"
             "Content-Type: application/sdp\r\n"
             "Max-Forwards: 70",
             contact_hdr);

    char *invite = sip_build_message(0, NULL, &tmpl, extra, fwd_sdp);
    free(fwd_sdp);
    free(rewritten);

    if (invite && tst && tst->fd > 0) {
      ssize_t sent =
          sendto(tst->fd, invite, strlen(invite), 0, (struct sockaddr *)&tst->remote_addr, tst->remote_addr_len);
      free(invite);
      if (sent > 0) {
        log_info("trunk failover: sent INVITE to trunk '%s' (%zd bytes)", tcfg->name, sent);
        found_next = 1;
        free(src_reg);
        return;
      }
    } else {
      free(invite);
    }
  }

  if (!found_next) {
    /* All trunks exhausted */
    log_warn("trunk: all trunks exhausted for call %s", msg->call_id);
    if (call->source_via) sip_replace_via(msg, call->source_via);
    char *resp503 = sip_build_message(503, "Service Unavailable", msg, NULL, NULL);
    if (resp503) {
      sendto(pbx_transport_get_sip_fd(), resp503, strlen(resp503), 0, (struct sockaddr *)&src_reg->remote_addr,
             sizeof(src_reg->remote_addr));
      free(resp503);
    }
    pbx_media_proxy_session_destroy(msg->call_id);
    pbx_call_delete(msg->call_id);
  }

  free(src_reg);
}

/* ------------------------------------------------------------------ */
/* protothread                                                         */
/* ------------------------------------------------------------------ */

int trunk_register_pt(int64_t timestamp, struct pt_task *task) {
  trunk_state_t *s   = (trunk_state_t *)task->udata;
  time_t         now = (time_t)(timestamp / 1000);

  if (!s || !s->cfg) {
    log_error("trunk: protothread has no state");
    return SCHED_ERROR;
  }

  /* Create socket on first run */
  if (s->fd <= 0) {
    if (trunk_resolve_remote(s) != 0) {
      s->retry_count++;
      int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
      if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
      s->next_register = now + (time_t)backoff;
      return SCHED_RUNNING;
    }

    int af = s->remote_addr.ss_family;
    s->fd  = socket(af, SOCK_DGRAM, 0);
    if (s->fd < 0) {
      log_error("trunk[%s]: failed to create socket", s->cfg->name);
      s->fd = 0;
      s->retry_count++;
      int backoff = 1 << (s->retry_count > 6 ? 6 : s->retry_count);
      if (backoff > TRUNK_BACKOFF_MAX) backoff = TRUNK_BACKOFF_MAX;
      s->next_register = now + (time_t)backoff;
      return SCHED_RUNNING;
    }

    /* Bind to ephemeral port so we can discover our local port.
     * All trunk communication goes through this socket; the Via header
     * must advertise this port so the trunk server sends responses back
     * to the same fd. */
    {
      struct sockaddr_in bind_addr;
      memset(&bind_addr, 0, sizeof(bind_addr));
      bind_addr.sin_family      = AF_INET;
      bind_addr.sin_addr.s_addr = INADDR_ANY;
      bind_addr.sin_port        = 0; /* let kernel pick */
      if (bind(s->fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        log_error("trunk[%s]: failed to bind socket", s->cfg->name);
      }
      struct sockaddr_in local_addr;
      socklen_t          local_len = sizeof(local_addr);
      if (getsockname(s->fd, (struct sockaddr *)&local_addr, &local_len) == 0) {
        s->local_port = ntohs(local_addr.sin_port);
      } else {
        s->local_port = 5060;
      }
    }

    set_socket_nonblocking(s->fd, 1);
    s->fds[0] = 1;
    s->fds[1] = s->fd;

    trunk_generate_call_id(s);
    s->next_register = now; /* register immediately */

    log_info("trunk[%s]: socket ready (fd=%d, local_port=%d)", s->cfg->name, s->fd, s->local_port);
  }

  /* Check for incoming data */
  int ready = sched_has_data(s->fds);
  if (ready > 0) {
    struct sockaddr_storage from_addr;
    socklen_t               from_len = sizeof(from_addr);
    ssize_t n = recvfrom(s->fd, s->recv_buf, sizeof(s->recv_buf) - 1, 0, (struct sockaddr *)&from_addr, &from_len);
    if (n > 0) {
      s->recv_buf[n] = '\0';
      log_trace("trunk[%s]: received %zd bytes", s->cfg->name, n);
      trunk_handle_response(s, now);
    }
  }

  /* Time to (re)register? */
  if (now >= s->next_register) {
    trunk_send_register(s);
    /* Set a response timeout - if no response comes, we'll retry */
    s->next_register = now + TRUNK_RESPONSE_TIMEOUT;
  }

  return SCHED_RUNNING;
}

/* ------------------------------------------------------------------ */
/* config parsing                                                      */
/* ------------------------------------------------------------------ */

static trunk_config_t *trunk_parse_section(const char *name, resp_object *sec) {
  trunk_config_t *cfg = calloc(1, sizeof(trunk_config_t));
  if (!cfg) return NULL;

  cfg->name = strdup(name);

  /* Parse address URL */
  resp_object *addr_arr = resp_map_get(sec, "address");
  const char  *addr_str = NULL;
  if (addr_arr && addr_arr->type == RESPT_ARRAY && addr_arr->u.arr.n > 0) {
    addr_str = addr_arr->u.arr.elem[0].u.s;
  }
  if (!addr_str) {
    addr_str = resp_map_get_string(sec, "address");
  }

  if (!addr_str) {
    log_error("trunk[%s]: missing 'address' field", name);
    trunk_config_free_fields(cfg);
    free(cfg);
    return NULL;
  }

  struct parsed_url *url = parse_url(addr_str);
  if (!url) {
    log_error("trunk[%s]: failed to parse address '%s': %s", name, addr_str, parse_url_last_error());
    trunk_config_free_fields(cfg);
    free(cfg);
    return NULL;
  }

  cfg->protocol = url->scheme ? strdup(url->scheme) : strdup("udp");
  cfg->host     = url->host ? strdup(url->host) : NULL;
  cfg->port     = url->port ? atoi(url->port) : 5060;
  cfg->username = url->username ? strdup(url->username) : NULL;
  cfg->password = url->password ? strdup(url->password) : NULL;
  parsed_url_free(url);

  if (!cfg->host || !cfg->host[0]) {
    log_error("trunk[%s]: address has no host", name);
    trunk_config_free_fields(cfg);
    free(cfg);
    return NULL;
  }

  /* CID (single value) */
  const char *cid = resp_map_get_string(sec, "cid");
  cfg->cid        = cid ? strdup(cid) : NULL;

  /* DIDs (repeatable array) */
  resp_object *did_arr = resp_map_get(sec, "did");
  if (did_arr && did_arr->type == RESPT_ARRAY) {
    cfg->did_count = did_arr->u.arr.n;
    cfg->dids      = calloc(cfg->did_count, sizeof(char *));
    for (size_t i = 0; i < cfg->did_count; i++) {
      if (did_arr->u.arr.elem[i].type == RESPT_BULK || did_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
        cfg->dids[i] = strdup(did_arr->u.arr.elem[i].u.s);
      }
    }
  }

  /* Groups (repeatable array) */
  resp_object *group_arr = resp_map_get(sec, "group");
  if (group_arr && group_arr->type == RESPT_ARRAY) {
    cfg->group_count = group_arr->u.arr.n;
    cfg->groups      = calloc(cfg->group_count, sizeof(char *));
    for (size_t i = 0; i < cfg->group_count; i++) {
      if (group_arr->u.arr.elem[i].type == RESPT_BULK || group_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
        cfg->groups[i] = strdup(group_arr->u.arr.elem[i].u.s);
      }
    }
  }

  /* Rewrite rules (alternating rewrite_pattern / rewrite_replace arrays) */
  resp_object *pat_arr = resp_map_get(sec, "rewrite_pattern");
  resp_object *rep_arr = resp_map_get(sec, "rewrite_replace");
  if (pat_arr && rep_arr && pat_arr->type == RESPT_ARRAY && rep_arr->type == RESPT_ARRAY) {
    size_t count = pat_arr->u.arr.n < rep_arr->u.arr.n ? pat_arr->u.arr.n : rep_arr->u.arr.n;
    if (pat_arr->u.arr.n != rep_arr->u.arr.n) {
      log_warn("trunk[%s]: rewrite_pattern count (%zu) != rewrite_replace count (%zu), using min", name,
               pat_arr->u.arr.n, rep_arr->u.arr.n);
    }
    cfg->rewrite_rules      = calloc(count, sizeof(trunk_rewrite_rule_t));
    cfg->rewrite_rule_count = 0;
    for (size_t i = 0; i < count; i++) {
      const char *pat_s = NULL;
      const char *rep_s = NULL;
      if (pat_arr->u.arr.elem[i].type == RESPT_BULK || pat_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
        pat_s = pat_arr->u.arr.elem[i].u.s;
      }
      if (rep_arr->u.arr.elem[i].type == RESPT_BULK || rep_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
        rep_s = rep_arr->u.arr.elem[i].u.s;
      }
      if (!pat_s || !rep_s) continue;

      char errbuf[256];
      int  rc = regcomp(&cfg->rewrite_rules[cfg->rewrite_rule_count].compiled, pat_s, REG_EXTENDED | REG_ICASE);
      if (rc != 0) {
        regerror(rc, &cfg->rewrite_rules[cfg->rewrite_rule_count].compiled, errbuf, sizeof(errbuf));
        log_error("trunk[%s]: rewrite_pattern[%zu] failed to compile '%s': %s", name, i, pat_s, errbuf);
        regfree(&cfg->rewrite_rules[cfg->rewrite_rule_count].compiled);
        continue;
      }
      cfg->rewrite_rules[cfg->rewrite_rule_count].pattern     = strdup(pat_s);
      cfg->rewrite_rules[cfg->rewrite_rule_count].replacement = strdup(rep_s);
      cfg->rewrite_rule_count++;
      log_debug("trunk[%s]: rewrite rule[%zu]: '%s' -> '%s'", name, cfg->rewrite_rule_count - 1, pat_s, rep_s);
    }
  }

  log_info("trunk[%s]: parsed config host=%s port=%d user=%s cid=%s dids=%zu groups=%zu rewrites=%zu", name, cfg->host,
           cfg->port, cfg->username ? cfg->username : "(none)", cfg->cid ? cfg->cid : "(none)", cfg->did_count,
           cfg->group_count, cfg->rewrite_rule_count);

  return cfg;
}

/* ------------------------------------------------------------------ */
/* spawn / teardown                                                    */
/* ------------------------------------------------------------------ */

static void trunk_spawn(trunk_config_t *cfg) {
  trunk_state_t *state = calloc(1, sizeof(trunk_state_t));
  state->cfg           = cfg;

  sched_create(trunk_register_pt, state);

  /* Walk the scheduler list to find the task we just created
   * (it's prepended as head) so we can store the handle. */
  extern pt_task_t *pt_first;
  trunk_entry_t    *entry = trunk_list;
  while (entry) {
    if (&entry->cfg == cfg) {
      entry->task = pt_first;
      break;
    }
    entry = entry->next;
  }
}

static void trunk_teardown(trunk_entry_t *entry) {
  if (entry->task) {
    trunk_state_t *s = (trunk_state_t *)entry->task->udata;
    trunk_state_free(s);
    entry->task->udata = NULL;
    sched_remove(entry->task);
    entry->task = NULL;
  }
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

void pbx_trunk_init(void) {
  if (!domain_cfg) return;

  /* Iterate config map for "trunk:*" keys */
  for (size_t i = 0; i + 1 < domain_cfg->u.arr.n; i += 2) {
    if (domain_cfg->u.arr.elem[i].type != RESPT_BULK && domain_cfg->u.arr.elem[i].type != RESPT_SIMPLE) continue;

    const char *key = domain_cfg->u.arr.elem[i].u.s;
    if (!key || strncmp(key, "trunk:", 6) != 0) continue;

    const char  *trunk_name = key + 6;
    resp_object *sec        = resp_map_get(domain_cfg, key);
    if (!sec || sec->type != RESPT_ARRAY) continue;

    trunk_config_t *cfg = trunk_parse_section(trunk_name, sec);
    if (!cfg) continue;

    /* Add to registry */
    trunk_entry_t *entry = calloc(1, sizeof(trunk_entry_t));
    entry->cfg           = *cfg; /* struct copy */
    free(cfg);                   /* free the container, fields are now in entry->cfg */
    entry->next = trunk_list;
    trunk_list  = entry;

    /* Spawn protothread */
    trunk_spawn(&entry->cfg);
  }
}

void pbx_trunk_shutdown(void) {
  trunk_entry_t *entry = trunk_list;
  while (entry) {
    trunk_entry_t *next = entry->next;
    trunk_teardown(entry);
    trunk_config_free_fields(&entry->cfg);
    free(entry);
    entry = next;
  }
  trunk_list = NULL;
}

void pbx_trunk_reload(void) {
  if (!domain_cfg) return;

  /* Build a set of trunk names from the new config */
  /* For each existing trunk, check if config changed; for new ones, spawn */

  /* Pass 1: mark existing entries, detect changes */
  trunk_entry_t *entry = trunk_list;
  while (entry) {
    char key[64];
    snprintf(key, sizeof(key), "trunk:%s", entry->cfg.name);
    resp_object *sec = resp_map_get(domain_cfg, key);

    if (!sec || sec->type != RESPT_ARRAY) {
      /* Trunk removed from config - teardown */
      log_info("trunk[%s]: removed from config, stopping", entry->cfg.name);
      trunk_teardown(entry);
      entry = entry->next;
      continue;
    }

    /* Re-parse and compare address (the critical field) */
    trunk_config_t *new_cfg = trunk_parse_section(entry->cfg.name, sec);
    if (!new_cfg) {
      trunk_teardown(entry);
      entry = entry->next;
      continue;
    }

    int changed = 0;
    if (strcmp_null(entry->cfg.host, new_cfg->host) != 0) changed = 1;
    if (entry->cfg.port != new_cfg->port) changed = 1;
    if (strcmp_null(entry->cfg.username, new_cfg->username) != 0) changed = 1;
    if (strcmp_null(entry->cfg.password, new_cfg->password) != 0) changed = 1;

    if (changed) {
      log_info("trunk[%s]: config changed, restarting", entry->cfg.name);
      trunk_teardown(entry);
      trunk_config_free_fields(&entry->cfg);
      entry->cfg = *new_cfg;
      free(new_cfg);
      trunk_spawn(&entry->cfg);
    } else {
      /* Update non-critical fields in place */
      free(entry->cfg.cid);
      entry->cfg.cid = new_cfg->cid;
      new_cfg->cid   = NULL;

      for (size_t i = 0; i < entry->cfg.did_count; i++) free(entry->cfg.dids[i]);
      free(entry->cfg.dids);
      entry->cfg.dids      = new_cfg->dids;
      entry->cfg.did_count = new_cfg->did_count;
      new_cfg->dids        = NULL;
      new_cfg->did_count   = 0;

      for (size_t i = 0; i < entry->cfg.group_count; i++) free(entry->cfg.groups[i]);
      free(entry->cfg.groups);
      entry->cfg.groups      = new_cfg->groups;
      entry->cfg.group_count = new_cfg->group_count;
      new_cfg->groups        = NULL;
      new_cfg->group_count   = 0;

      for (size_t i = 0; i < entry->cfg.rewrite_rule_count; i++) {
        free(entry->cfg.rewrite_rules[i].pattern);
        free(entry->cfg.rewrite_rules[i].replacement);
        regfree(&entry->cfg.rewrite_rules[i].compiled);
      }
      free(entry->cfg.rewrite_rules);
      entry->cfg.rewrite_rules      = new_cfg->rewrite_rules;
      entry->cfg.rewrite_rule_count = new_cfg->rewrite_rule_count;
      new_cfg->rewrite_rules        = NULL;
      new_cfg->rewrite_rule_count   = 0;

      trunk_config_free_fields(new_cfg);
      free(new_cfg);
    }

    entry = entry->next;
  }

  /* Pass 2: find new trunks not in the list */
  for (size_t i = 0; i + 1 < domain_cfg->u.arr.n; i += 2) {
    if (domain_cfg->u.arr.elem[i].type != RESPT_BULK && domain_cfg->u.arr.elem[i].type != RESPT_SIMPLE) continue;

    const char *key = domain_cfg->u.arr.elem[i].u.s;
    if (!key || strncmp(key, "trunk:", 6) != 0) continue;

    const char *trunk_name = key + 6;

    /* Check if already in list */
    int            found = 0;
    trunk_entry_t *e     = trunk_list;
    while (e) {
      if (e->cfg.name && strcmp(e->cfg.name, trunk_name) == 0) {
        found = 1;
        break;
      }
      e = e->next;
    }
    if (found) continue;

    resp_object *sec = resp_map_get(domain_cfg, key);
    if (!sec || sec->type != RESPT_ARRAY) continue;

    trunk_config_t *cfg = trunk_parse_section(trunk_name, sec);
    if (!cfg) continue;

    trunk_entry_t *new_entry = calloc(1, sizeof(trunk_entry_t));
    new_entry->cfg           = *cfg;
    free(cfg);
    new_entry->next = trunk_list;
    trunk_list      = new_entry;

    trunk_spawn(&new_entry->cfg);
    log_info("trunk[%s]: new trunk detected, starting", trunk_name);
  }

  /* Pass 3: remove entries that were torn down (no task) and have no config */
  trunk_entry_t **pp = &trunk_list;
  while (*pp) {
    trunk_entry_t *cur = *pp;
    if (!cur->task) {
      char key[64];
      snprintf(key, sizeof(key), "trunk:%s", cur->cfg.name);
      resp_object *sec = resp_map_get(domain_cfg, key);
      if (!sec) {
        *pp = cur->next;
        trunk_config_free_fields(&cur->cfg);
        free(cur);
        continue;
      }
    }
    pp = &(*pp)->next;
  }
}

/* ------------------------------------------------------------------ */
/* outbound routing API                                                */
/* ------------------------------------------------------------------ */

int pbx_trunk_is_registered(trunk_state_t *state) {
  if (!state) return 0;
  if (state->registered_at == 0) return 0;
  time_t now = time(NULL);
  /* registered_at + expires_seconds gives the absolute expiry */
  if (state->registered_at + state->expires_seconds <= now) return 0;
  return 1;
}

size_t pbx_trunk_get_by_group(const char *group, trunk_config_t **cfgs_out, trunk_state_t **states_out,
                              size_t max_out) {
  size_t count = 0;
  if (!group) return 0;

  /* Walk trunk_list in order.  Note: trunk_list is built by prepending,
   * so the order is reversed compared to the config file.  We collect
   * into the output arrays and then reverse them so the caller sees
   * config-file order. */
  trunk_entry_t *entry = trunk_list;
  while (entry && count < max_out) {
    for (size_t g = 0; g < entry->cfg.group_count; g++) {
      if (entry->cfg.groups[g] && strcmp(entry->cfg.groups[g], group) == 0) {
        if (cfgs_out) cfgs_out[count] = &entry->cfg;
        if (states_out) {
          /* The state lives in the task's udata */
          states_out[count] = entry->task ? (trunk_state_t *)entry->task->udata : NULL;
        }
        count++;
        break; /* only count this trunk once even if group listed twice */
      }
    }
    entry = entry->next;
  }

  /* Reverse to restore config-file order */
  for (size_t i = 0; i < count / 2; i++) {
    size_t j = count - 1 - i;
    if (cfgs_out) {
      trunk_config_t *tc = cfgs_out[i];
      cfgs_out[i]        = cfgs_out[j];
      cfgs_out[j]        = tc;
    }
    if (states_out) {
      trunk_state_t *ts = states_out[i];
      states_out[i]     = states_out[j];
      states_out[j]     = ts;
    }
  }

  return count;
}

#define REWRITE_NMATCHES 10

char *pbx_trunk_apply_rewrite(const trunk_config_t *cfg, const char *dialed_number) {
  if (!cfg || !dialed_number) return dialed_number ? strdup(dialed_number) : NULL;

  for (size_t i = 0; i < cfg->rewrite_rule_count; i++) {
    regmatch_t pm[REWRITE_NMATCHES];
    if (regexec(&cfg->rewrite_rules[i].compiled, dialed_number, REWRITE_NMATCHES, pm, 0) != 0) {
      continue; /* no match */
    }

    /* First matching rule: perform replacement with backreference expansion */
    const char *rp = cfg->rewrite_rules[i].replacement;
    char        result[256];
    int         rpos = 0;

    for (const char *p = rp; *p && rpos < (int)sizeof(result) - 1; p++) {
      if (*p == '\\' && p[1] >= '1' && p[1] <= '9') {
        int idx = p[1] - '0';
        if (pm[idx].rm_so >= 0 && pm[idx].rm_eo >= pm[idx].rm_so) {
          int len = pm[idx].rm_eo - pm[idx].rm_so;
          if (rpos + len < (int)sizeof(result)) {
            memcpy(result + rpos, dialed_number + pm[idx].rm_so, len);
            rpos += len;
          }
        }
        p++; /* skip the digit */
      } else {
        result[rpos++] = *p;
      }
    }
    result[rpos] = '\0';

    log_debug("trunk[%s]: rewrite '%s' -> '%s' (rule %zu: '%s' -> '%s')", cfg->name, dialed_number, result, i,
              cfg->rewrite_rules[i].pattern, cfg->rewrite_rules[i].replacement);
    return strdup(result);
  }

  /* No rule matched: return original */
  return strdup(dialed_number);
}

int pbx_trunk_dispatch_call_response(const char *trunk_name, sip_message_t *msg) {
  if (!trunk_name || !msg) return -1;

  trunk_entry_t *entry = trunk_list;
  while (entry) {
    if (entry->cfg.name && strcmp(entry->cfg.name, trunk_name) == 0) {
      trunk_state_t *state = entry->task ? (trunk_state_t *)entry->task->udata : NULL;
      if (state) {
        trunk_handle_call_response(state, msg);
        return 0;
      }
      log_warn("trunk[%s]: no state available for dispatch", trunk_name);
      return -1;
    }
    entry = entry->next;
  }

  log_warn("trunk: dispatch - trunk '%s' not found", trunk_name);
  return -1;
}
