/*
 * Unified call state and rtpproxy session management.
 *
 * PBX communicates with rtpproxy via control protocol only.
 * All RTP relay is done by rtpproxy (external sippy or built-in).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common/socket_util.h"
#include "AppModule/call.h"
#include "AppModule/service/rtpproxy.h"
#include "AppModule/util/rtpproxy_client.h"
#include "rxi/log.h"

/* Linked list of active calls */

static call_t *call_list = NULL;

/* Pre-remove callback (e.g. for plugin CALL.HANGUP notifications). */
static call_pre_remove_cb pre_remove_cb = NULL;

void call_set_pre_remove_callback(call_pre_remove_cb cb) {
  pre_remove_cb = cb;
}

/* Lifecycle */

call_t *call_create(const char *call_id) {
  log_trace("call_create: %.32s", call_id ? call_id : "");
  call_t *c = calloc(1, sizeof(*c));
  if (!c) return NULL;
  if (call_id)
    snprintf(c->call_id, sizeof(c->call_id), "%s", call_id);
  c->created_at    = time(NULL);
  c->ext_sdp_is_tcp = -1;  /* Not specified by default */
  /* Link into list. */
  c->next   = call_list;
  call_list = c;
  return c;
}

call_t *call_find(const char *call_id) {
  if (!call_id || !call_id[0]) return NULL;
  for (call_t *c = call_list; c; c = c->next)
    if (strcmp(c->call_id, call_id) == 0) return c;
  return NULL;
}

void call_remove(call_t *call) {
  if (!call) return;
  log_trace("call_remove: %.32s", call->call_id);

  /* Invoke pre-remove callback (e.g. CALL.HANGUP plugin notification). */
  if (pre_remove_cb)
    pre_remove_cb(call);

  /* Cleanup rtpproxy sessions */
  call_rtpproxy_session_delete(call);

  /* Unlink from list. */
  if (call_list == call) {
    call_list = call->next;
  } else {
    for (call_t *p = call_list; p; p = p->next) {
      if (p->next == call) { p->next = call->next; break; }
    }
  }

  /* Free strings. */
  free(call->a.id);   call->a.id  = NULL;
  free(call->a.tag);  call->a.tag = NULL;
  free(call->b.id);   call->b.id  = NULL;
  free(call->b.tag);  call->b.tag = NULL;
  for (size_t i = 0; i < call->n_forks; i++) {
    free(call->fork_ids[i]);
    free(call->fork_vias[i]);
  }
  for (size_t i = 0; i < call->n_pending_exts; i++)
    free(call->pending_exts[i]);
  free(call->original_invite);
  free(call->caller_via);
  free(call->source_str);
  free(call->dest_str);
  free(call->direction);
  free(call->trunk_name);
  free(call);
}

call_t *call_first(void) { return call_list; }

/* rtpproxy session management via control protocol */

int call_rtpproxy_session_create(call_t *call, int side_caller,
                                  const char *from_tag, const char *to_tag) {
  if (!call) return -1;

  rtpp_client_t *client = rtpproxy_get_client();
  if (!client) {
    log_error("call: no rtpproxy available");
    return -1;
  }

  /* Store tags for session management */
  if (side_caller) {
    if (from_tag) {
      strncpy(call->rtp_session_caller, from_tag, sizeof(call->rtp_session_caller) - 1);
    }
    if (to_tag) {
      strncpy(call->rtp_session_callee, to_tag, sizeof(call->rtp_session_callee) - 1);
    }
  } else {
    if (from_tag) {
      strncpy(call->rtp_session_callee, from_tag, sizeof(call->rtp_session_callee) - 1);
    }
    if (to_tag) {
      strncpy(call->rtp_session_caller, to_tag, sizeof(call->rtp_session_caller) - 1);
    }
  }

  int port = 0;
  char rtp_ip[64] = {0};
  log_trace("rtpproxy: creating session call=%.32s caller_tag=%.32s callee_tag=%.32s",
            call->call_id, call->rtp_session_caller, call->rtp_session_callee);
  int r = rtpp_update(client, call->call_id, "0.0.0.0", 0,
                      call->rtp_session_caller[0] ? call->rtp_session_caller : call->call_id,
                      call->rtp_session_callee[0] ? call->rtp_session_callee : NULL,
                      NULL, &port, rtp_ip, sizeof(rtp_ip));
  log_trace("rtpproxy: rtpp_update returned r=%d port=%d rtp_ip=%.32s", r, port, rtp_ip);
  if (r != 0 || port <= 0) {
    log_error("call: rtpproxy session create failed (r=%d, port=%d)", r, port);
    return -1;
  }

  /* Store the info for SDP */
  if (side_caller) {
    call->rtp_port_caller = port;
    if (rtp_ip[0]) {
      size_t n = strlen(rtp_ip);
      if (n >= sizeof(call->rtp_proxy_ip_caller)) n = sizeof(call->rtp_proxy_ip_caller) - 1;
      memcpy(call->rtp_proxy_ip_caller, rtp_ip, n);
      call->rtp_proxy_ip_caller[n] = '\0';
    } else {
      const char *fallback = rtpproxy_get_fallback_ip();
      if (fallback) {
        size_t n = strlen(fallback);
        if (n >= sizeof(call->rtp_proxy_ip_caller)) n = sizeof(call->rtp_proxy_ip_caller) - 1;
        memcpy(call->rtp_proxy_ip_caller, fallback, n);
        call->rtp_proxy_ip_caller[n] = '\0';
      }
    }
  } else {
    call->rtp_port_callee = port;
    if (rtp_ip[0]) {
      size_t n = strlen(rtp_ip);
      if (n >= sizeof(call->rtp_proxy_ip_callee)) n = sizeof(call->rtp_proxy_ip_callee) - 1;
      memcpy(call->rtp_proxy_ip_callee, rtp_ip, n);
      call->rtp_proxy_ip_callee[n] = '\0';
    } else {
      const char *fallback = rtpproxy_get_fallback_ip();
      if (fallback) {
        size_t n = strlen(fallback);
        if (n >= sizeof(call->rtp_proxy_ip_callee)) n = sizeof(call->rtp_proxy_ip_callee) - 1;
        memcpy(call->rtp_proxy_ip_callee, fallback, n);
        call->rtp_proxy_ip_callee[n] = '\0';
      }
    }
  }

  log_trace("call: created rtpproxy session side=%s call=%.32s port=%d ip=%s",
            side_caller ? "caller" : "callee", call->call_id, port,
            side_caller ? call->rtp_proxy_ip_caller : call->rtp_proxy_ip_callee);
  return 0;
}

int call_rtpproxy_session_delete(call_t *call) {
  if (!call) return -1;

  rtpp_client_t *client = rtpproxy_get_client();
  if (!client) {
    log_error("call: no rtpproxy available for session delete");
    return -1;
  }

  int errors = 0;

  /* Delete caller session */
  if (call->rtp_session_caller[0]) {
    int r = rtpp_delete(client, call->call_id,
                        call->rtp_session_caller[0] ? call->rtp_session_caller : NULL,
                        call->rtp_session_callee[0] ? call->rtp_session_callee : NULL,
                        0);
    if (r != 0) {
      log_warn("call: rtpproxy session delete failed for caller");
      errors++;
    } else {
      log_trace("call: deleted rtpproxy session caller call=%.32s", call->call_id);
    }
  }

  /* Clear session data */
  call->rtp_session_caller[0] = '\0';
  call->rtp_session_callee[0] = '\0';
  call->rtp_port_caller = 0;
  call->rtp_port_callee = 0;
  call->rtp_proxy_ip_caller[0] = '\0';
  call->rtp_proxy_ip_callee[0] = '\0';

  return errors > 0 ? -1 : 0;
}

void call_age_idle(int timeout_sec) {
  time_t cutoff = time(NULL) - timeout_sec;
  call_t *c = call_list;
  while (c) {
    call_t *next = c->next;
    if (c->created_at < cutoff) {
      log_debug("call: aging idle call %.32s (timeout %ds)",
               c->call_id, timeout_sec);
      call_remove(c);
    }
    c = next;
  }
}

void call_set_transport(call_t *call, int side_a, const char *transport) {
  if (!call || !transport) return;
  char *dest = side_a ? call->transport_caller : call->transport_callee;
  strncpy(dest, transport, sizeof(call->transport_caller) - 1);
  dest[sizeof(call->transport_caller) - 1] = '\0';
}