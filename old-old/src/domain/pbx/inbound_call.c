#include "domain/pbx/inbound_call.h"

#include <stdlib.h>
#include <string.h>

#include "domain/pbx/media_proxy.h"
#include "rxi/log.h"

#define INITIAL_LEG_CAPACITY 8

static inbound_call_t **inbound_calls     = NULL;
static size_t           inbound_call_count = 0;
static size_t           inbound_call_capacity = 0;

void inbound_call_init(void) {
  inbound_calls        = NULL;
  inbound_call_count   = 0;
  inbound_call_capacity = 0;
  log_info("inbound_call: initialized");
}

void inbound_call_shutdown(void) {
  if (!inbound_calls) return;
  for (size_t i = 0; i < inbound_call_count; i++) {
    if (inbound_calls[i]) {
      inbound_call_delete(inbound_calls[i]->trunk_call_id);
    }
  }
  free(inbound_calls);
  inbound_calls        = NULL;
  inbound_call_count   = 0;
  inbound_call_capacity = 0;
}

void inbound_call_free_leg(inbound_leg_t *leg) {
  if (!leg) return;
  free(leg->media_ports);
  free(leg->rtcp_ports);
  free(leg->advertise_addr);
  free(leg->from_tag);
  free(leg->to_tag);
  free(leg->leg_to);
  free(leg->branch);
  free(leg);
}

static void inbound_call_free(inbound_call_t *call) {
  if (!call) return;
  free(call->trunk_call_id);
  free(call->trunk_name);
  free(call->trunk_media_ports);
  free(call->trunk_rtcp_ports);
  free(call->trunk_advertise_addr);
  free(call->trunk_remote_ip);
  free(call->trunk_remote_media_ports);
  free(call->trunk_from);
  free(call->trunk_to);
  free(call->trunk_to_tag);
  free(call->trunk_via);
  free(call->trunk_contact);
  free(call->trunk_sdp);
  free(call->rtp_session_id);
  free(call->did);
  free(call->answered_extension);
  for (size_t i = 0; i < call->leg_count; i++) {
    inbound_call_free_leg(call->legs[i]);
  }
  free(call->legs);
  free(call);
}

inbound_call_t *inbound_call_create(const char *call_id, const char *trunk_name) {
  if (!call_id || !trunk_name) return NULL;

  if (inbound_call_find(call_id)) {
    log_warn("inbound_call: call %s already exists", call_id);
    return NULL;
  }

  if (inbound_call_count >= inbound_call_capacity) {
    size_t new_capacity = inbound_call_capacity == 0 ? 16 : inbound_call_capacity * 2;
    inbound_call_t **new_calls = realloc(inbound_calls, new_capacity * sizeof(inbound_call_t *));
    if (!new_calls) return NULL;
    inbound_calls        = new_calls;
    inbound_call_capacity = new_capacity;
  }

  inbound_call_t *call = calloc(1, sizeof(inbound_call_t));
  if (!call) return NULL;

  call->trunk_call_id = strdup(call_id);
  call->trunk_name    = strdup(trunk_name);

  call->leg_capacity = INITIAL_LEG_CAPACITY;
  call->legs         = calloc(call->leg_capacity, sizeof(inbound_leg_t *));
  if (!call->legs) {
    free(call->trunk_call_id);
    free(call->trunk_name);
    free(call);
    return NULL;
  }

  call->leg_cseq_counter = 1;

  inbound_calls[inbound_call_count++] = call;

  log_debug("inbound_call: created call %s for trunk %s", call_id, trunk_name);
  return call;
}

inbound_call_t *inbound_call_find(const char *call_id) {
  if (!call_id) return NULL;
  for (size_t i = 0; i < inbound_call_count; i++) {
    if (inbound_calls[i] && inbound_calls[i]->trunk_call_id &&
        strcmp(inbound_calls[i]->trunk_call_id, call_id) == 0) {
      return inbound_calls[i];
    }
  }
  return NULL;
}

void inbound_call_delete(const char *call_id) {
  if (!call_id) return;
  for (size_t i = 0; i < inbound_call_count; i++) {
    if (inbound_calls[i] && inbound_calls[i]->trunk_call_id &&
        strcmp(inbound_calls[i]->trunk_call_id, call_id) == 0) {
      log_debug("inbound_call: deleting call %s", call_id);
      if (inbound_calls[i]->rtp_session_id) {
        pbx_media_proxy_session_destroy(inbound_calls[i]->rtp_session_id);
      }
      inbound_call_free(inbound_calls[i]);
      inbound_calls[i] = inbound_calls[--inbound_call_count];
      inbound_calls[inbound_call_count] = NULL;
      return;
    }
  }
}

inbound_leg_t *inbound_call_add_leg(inbound_call_t *call, const char *extension) {
  if (!call || !extension) return NULL;

  for (size_t i = 0; i < call->leg_count; i++) {
    if (call->legs[i] && strcmp(call->legs[i]->extension, extension) == 0) {
      log_warn("inbound_call: leg for extension %s already exists", extension);
      return call->legs[i];
    }
  }

  if (call->leg_count >= call->leg_capacity) {
    size_t new_capacity = call->leg_capacity * 2;
    inbound_leg_t **new_legs = realloc(call->legs, new_capacity * sizeof(inbound_leg_t *));
    if (!new_legs) return NULL;
    call->legs        = new_legs;
    call->leg_capacity = new_capacity;
  }

  inbound_leg_t *leg = calloc(1, sizeof(inbound_leg_t));
  if (!leg) return NULL;

  strncpy(leg->extension, extension, sizeof(leg->extension) - 1);
  leg->state = INBOUND_LEG_PENDING;

  call->legs[call->leg_count++] = leg;

  log_debug("inbound_call: added leg for extension %s to call %s", extension, call->trunk_call_id);
  return leg;
}

inbound_leg_t *inbound_call_find_leg(inbound_call_t *call, const char *extension) {
  if (!call || !extension) return NULL;
  for (size_t i = 0; i < call->leg_count; i++) {
    if (call->legs[i] && strcmp(call->legs[i]->extension, extension) == 0) {
      return call->legs[i];
    }
  }
  return NULL;
}

void inbound_call_destroy_leg_sockets(inbound_call_t *call, inbound_leg_t *leg) {
  if (!call || !leg || !call->rtp_session_id) return;

  for (int i = 0; i < leg->media_port_count; i++) {
    char socket_id[128];
    snprintf(socket_id, sizeof(socket_id), "%s-leg-%s-%d", call->rtp_session_id, leg->extension, i);
    pbx_media_proxy_destroy_socket(call->rtp_session_id, socket_id);
  }
  for (int i = 0; i < leg->rtcp_port_count; i++) {
    char socket_id[128];
    snprintf(socket_id, sizeof(socket_id), "%s-leg-%s-rtcp-%d", call->rtp_session_id, leg->extension, i);
    pbx_media_proxy_destroy_socket(call->rtp_session_id, socket_id);
  }

  free(leg->media_ports);
  free(leg->rtcp_ports);
  leg->media_ports    = NULL;
  leg->rtcp_ports     = NULL;
  leg->media_port_count = 0;
  leg->rtcp_port_count  = 0;
}

int inbound_call_all_legs_terminated(inbound_call_t *call) {
  if (!call) return 1;
  for (size_t i = 0; i < call->leg_count; i++) {
    inbound_leg_t *leg = call->legs[i];
    if (!leg) continue;
    if (leg->state == INBOUND_LEG_PENDING || leg->state == INBOUND_LEG_RINGING) {
      return 0;
    }
  }
  return 1;
}

int inbound_call_select_final_status(inbound_call_t *call) {
  if (!call) return 480;

  for (size_t i = 0; i < call->leg_count; i++) {
    if (call->legs[i] && call->legs[i]->state == INBOUND_LEG_FAILED && call->legs[i]->final_status == 486) {
      return 486;
    }
  }
  return 480;
}
