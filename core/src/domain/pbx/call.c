#include "domain/pbx/call.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "domain/pbx/group.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sdp_parse.h"
#include "domain/pbx/sip/udphole_client.h"
#include "rxi/log.h"
#include "tidwall/hashmap.h"

#define CALL_TIMEOUT_SEC 3600
#define RING_TIMEOUT_SEC 60

static struct hashmap *calls = NULL;

static uint64_t call_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  const call_t *c = item;
  return hashmap_sip(c->call_id, strlen(c->call_id), seed0, seed1);
}

static int call_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  const call_t *ca = a;
  const call_t *cb = b;
  return strcmp(ca->call_id, cb->call_id);
}

static const call_t *find_call(const char *call_id) {
  if (!calls || !call_id) return NULL;
  call_t key = {.call_id = (char *)call_id};
  return hashmap_get(calls, &key);
}

static const char *get_advertise_ip(void) {
  const char *adv = udphole_get_advertise_addr();
  if (adv && adv[0]) return adv;
  return NULL;
}

static void free_call(const call_t *c) {
  if (!c) return;
  free((void*)c->call_id);
  free((void*)c->source_ext);
  free((void*)c->dest_ext);
  free((void*)c->source_contact);
  free((void*)c->dest_contact);
  free((void*)c->from_tag);
  free((void*)c->to_tag);
  for (int i = 0; i < c->num_media_streams; i++) {
    free(c->source_socket_ids[i]);
    free(c->dest_socket_ids[i]);
  }
  free((void*)c);
}

void call_init(void) {
  if (calls) return;
  calls = hashmap_new(sizeof(call_t), 64, 0, 0, call_hash, call_compare, NULL, NULL);
}

const call_t *call_find(const char *call_id) {
  return find_call(call_id);
}

int call_route_invite(const char *from_ext, const char *to_ext, const char *call_id, const char *from_tag,
                      const char *sdp, size_t sdp_len, const char *source_ip, int source_port, char **out_sdp,
                      size_t *out_sdp_len, char **out_dest_sdp, size_t *out_dest_sdp_len) {
  log_info("call: %s -> %s, call_id=%s, from_tag=%s", from_ext, to_ext, call_id, from_tag);

  registration_t *source_reg = registration_find(from_ext);
  if (!source_reg) {
    log_error("call: source extension %s not registered", from_ext);
    return -1;
  }

  char source_reg_ip[INET6_ADDRSTRLEN] = {0};
  int  source_reg_port                 = 0;
  if (source_reg->remote_addr.ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&source_reg->remote_addr;
    inet_ntop(AF_INET, &sin->sin_addr, source_reg_ip, sizeof(source_reg_ip));
    source_reg_port = ntohs(sin->sin_port);
  } else if (source_reg->remote_addr.ss_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&source_reg->remote_addr;
    inet_ntop(AF_INET6, &sin6->sin6_addr, source_reg_ip, sizeof(source_reg_ip));
    source_reg_port = ntohs(sin6->sin6_port);
  }

  if (strcmp(source_ip, source_reg_ip) != 0 || source_port != source_reg_port) {
    log_error("call: source IP mismatch: expected %s:%d, got %s:%d", source_reg_ip, source_reg_port, source_ip,
              source_port);
    return -1;
  }

  const char *source_group = source_reg->group;

  char group_candidate[128] = {0};
  if (source_group) {
    snprintf(group_candidate, sizeof(group_candidate), "%s%s", source_group, to_ext);
  }

  registration_t *dest_reg = NULL;

  if (group_candidate[0]) {
    dest_reg = registration_find(group_candidate);
  }

  if (!dest_reg) {
    dest_reg = registration_find(to_ext);
  }

  if (!dest_reg && group_candidate[0]) {
    const char *best_pattern = registration_pattern_best_match(group_candidate);
    if (best_pattern) {
      dest_reg = registration_find(best_pattern);
    }
  }

  if (!dest_reg) {
    const char *best_pattern = registration_pattern_best_match(to_ext);
    if (best_pattern) {
      dest_reg = registration_find(best_pattern);
    }
  }

  if (!dest_reg) {
    log_error("call: destination extension %s not found (tried: %s, %s)", to_ext,
              group_candidate[0] ? group_candidate : "(none)", to_ext);
    return -2;
  }

  const char *dest_group = dest_reg->group;

  if (source_group && dest_group && strcmp(source_group, dest_group) != 0) {
    int src_outgoing = group_get_allow_outgoing_cross_group(source_group);
    int dest_incoming = group_get_allow_incoming_cross_group(dest_group);

    if (!src_outgoing || !dest_incoming) {
      log_error("call: cross-group call denied: source_group=%s, dest_group=%s, src_outgoing=%d, dest_incoming=%d",
                source_group ? source_group : "(none)", dest_group ? dest_group : "(none)", src_outgoing, dest_incoming);
      return -2;
    }
  }

  udphole_client_t *udphole = udphole_get_client();
  if (!udphole) {
    log_error("call: udphole not initialized");
    return -1;
  }

  sdp_media_t source_media[SDP_MAX_MEDIA];
  size_t      n_source_media = 0;
  if (sdp_parse_media(sdp, sdp_len, source_media, SDP_MAX_MEDIA, &n_source_media) != 0 || n_source_media == 0) {
    log_error("call: failed to parse source SDP");
    return -1;
  }

  if (udphole_session_create(udphole, call_id, CALL_TIMEOUT_SEC) != 0) {
    log_error("call: failed to create udphole session");
    return -1;
  }

  char dest_tag[] = "dest";
  udphole_socket_info_t source_info[MAX_MEDIA_STREAMS];
  udphole_socket_info_t dest_info[MAX_MEDIA_STREAMS];
  char                  *source_socket_ids[MAX_MEDIA_STREAMS];
  char                  *dest_socket_ids[MAX_MEDIA_STREAMS];

  for (size_t i = 0; i < n_source_media; i++) {
    source_socket_ids[i] = malloc(64);
    snprintf(source_socket_ids[i], 64, "%s_%zu", from_tag, i);
    if (udphole_socket_create_listen(udphole, call_id, source_socket_ids[i], &source_info[i]) != 0) {
      log_error("call: failed to create source socket %zu", i);
      for (size_t j = 0; j < i; j++) {
        udphole_socket_destroy(udphole, call_id, source_socket_ids[j]);
        free(source_socket_ids[j]);
        free(dest_socket_ids[j]);
      }
      udphole_session_destroy(udphole, call_id);
      return -1;
    }

    dest_socket_ids[i] = malloc(64);
    snprintf(dest_socket_ids[i], 64, "dest_%zu", i);
    if (udphole_socket_create_listen(udphole, call_id, dest_socket_ids[i], &dest_info[i]) != 0) {
      log_error("call: failed to create dest socket %zu", i);
      udphole_socket_destroy(udphole, call_id, source_socket_ids[i]);
      for (size_t j = 0; j < i; j++) {
        udphole_socket_destroy(udphole, call_id, source_socket_ids[j]);
        udphole_socket_destroy(udphole, call_id, dest_socket_ids[j]);
        free(source_socket_ids[j]);
        free(dest_socket_ids[j]);
      }
      free(source_socket_ids[i]);
      free(dest_socket_ids[i]);
      udphole_session_destroy(udphole, call_id);
      return -1;
    }

    if (udphole_forward_create(udphole, call_id, source_socket_ids[i], dest_socket_ids[i]) != 0) {
      log_error("call: failed to create forward source->dest %zu", i);
      udphole_socket_destroy(udphole, call_id, dest_socket_ids[i]);
      udphole_socket_destroy(udphole, call_id, source_socket_ids[i]);
      for (size_t j = 0; j < i; j++) {
        udphole_forward_destroy(udphole, call_id, source_socket_ids[j], dest_socket_ids[j]);
        udphole_forward_destroy(udphole, call_id, dest_socket_ids[j], source_socket_ids[j]);
        udphole_socket_destroy(udphole, call_id, source_socket_ids[j]);
        udphole_socket_destroy(udphole, call_id, dest_socket_ids[j]);
        free(source_socket_ids[j]);
        free(dest_socket_ids[j]);
      }
      free(source_socket_ids[i]);
      free(dest_socket_ids[i]);
      udphole_session_destroy(udphole, call_id);
      return -1;
    }

    if (udphole_forward_create(udphole, call_id, dest_socket_ids[i], source_socket_ids[i]) != 0) {
      log_error("call: failed to create forward dest->source %zu", i);
      udphole_forward_destroy(udphole, call_id, source_socket_ids[i], dest_socket_ids[i]);
      udphole_socket_destroy(udphole, call_id, dest_socket_ids[i]);
      udphole_socket_destroy(udphole, call_id, source_socket_ids[i]);
      for (size_t j = 0; j < i; j++) {
        udphole_forward_destroy(udphole, call_id, source_socket_ids[j], dest_socket_ids[j]);
        udphole_forward_destroy(udphole, call_id, dest_socket_ids[j], source_socket_ids[j]);
        udphole_socket_destroy(udphole, call_id, source_socket_ids[j]);
        udphole_socket_destroy(udphole, call_id, dest_socket_ids[j]);
        free(source_socket_ids[j]);
        free(dest_socket_ids[j]);
      }
      free(source_socket_ids[i]);
      free(dest_socket_ids[i]);
      udphole_session_destroy(udphole, call_id);
      return -1;
    }
  }

  call_t *c         = calloc(1, sizeof(*c));
  c->call_id        = strdup(call_id);
  c->source_ext     = strdup(from_ext);
  c->dest_ext       = strdup(to_ext);
  c->source_contact = strdup(source_reg->contact ? source_reg->contact : "");
  c->dest_contact   = strdup(dest_reg->contact ? dest_reg->contact : "");
  memcpy(&c->source_addr, &source_reg->remote_addr, sizeof(c->source_addr));
  memcpy(&c->dest_addr, &dest_reg->remote_addr, sizeof(c->dest_addr));
  c->from_tag = strdup(from_tag);
  c->to_tag   = strdup(dest_tag);
  c->created  = time(NULL);
  c->num_media_streams = (int)n_source_media;

  const char *adv = get_advertise_ip();

  for (size_t i = 0; i < n_source_media; i++) {
    if (source_info[i].advertise_ip && source_info[i].advertise_ip[0]) {
      strncpy(c->source_rtp_ip[i], source_info[i].advertise_ip, sizeof(c->source_rtp_ip[i]) - 1);
    } else if (adv) {
      strncpy(c->source_rtp_ip[i], adv, sizeof(c->source_rtp_ip[i]) - 1);
    }
    c->source_rtp_port[i] = source_info[i].port;
    c->source_socket_ids[i] = source_socket_ids[i];

    if (dest_info[i].advertise_ip && dest_info[i].advertise_ip[0]) {
      strncpy(c->dest_rtp_ip[i], dest_info[i].advertise_ip, sizeof(c->dest_rtp_ip[i]) - 1);
    } else if (adv) {
      strncpy(c->dest_rtp_ip[i], adv, sizeof(c->dest_rtp_ip[i]) - 1);
    }
    c->dest_rtp_port[i] = dest_info[i].port;
    c->dest_socket_ids[i] = dest_socket_ids[i];

    free(source_info[i].advertise_ip);
    free(dest_info[i].advertise_ip);
  }

  hashmap_set(calls, c);

  *out_sdp = malloc(4096);
  *out_dest_sdp = malloc(4096);
  if (!*out_sdp || !*out_dest_sdp) {
    free(*out_sdp);
    free(*out_dest_sdp);
    *out_sdp = NULL;
    *out_dest_sdp = NULL;
    free_call(c);
    return -1;
  }

  int len = sdp_rewrite_all_media(sdp, sdp_len, c->dest_rtp_ip, c->dest_rtp_port, (int)n_source_media, *out_sdp, 4096);
  if (len < 0) {
    free(*out_sdp);
    free(*out_dest_sdp);
    *out_sdp = NULL;
    *out_dest_sdp = NULL;
    free_call(c);
    return -1;
  }
  *out_sdp_len = (size_t)len;

  len = sdp_rewrite_all_media(sdp, sdp_len, c->source_rtp_ip, c->source_rtp_port, (int)n_source_media, *out_dest_sdp, 4096);
  if (len < 0) {
    free(*out_sdp);
    free(*out_dest_sdp);
    *out_sdp = NULL;
    *out_dest_sdp = NULL;
    free_call(c);
    return -1;
  }
  *out_dest_sdp_len = (size_t)len;

  log_info("call: session created with %zu media streams", n_source_media);
  for (size_t i = 0; i < n_source_media; i++) {
    log_info("call:   stream %zu: source_rtp=%s:%d, dest_rtp=%s:%d", i,
             c->source_rtp_ip[i], c->source_rtp_port[i],
             c->dest_rtp_ip[i], c->dest_rtp_port[i]);
  }

  return 0;
}

void call_handle_bye(const char *call_id) {
  const call_t *c = find_call(call_id);
  if (!c) {
    log_warn("call_bye: call not found: %s", call_id);
    return;
  }

  log_info("call_bye: call_id=%s", call_id);

  udphole_client_t *udphole = udphole_get_client();
  if (udphole) {
    for (int i = 0; i < c->num_media_streams; i++) {
      if (c->source_socket_ids[i]) {
        udphole_forward_destroy(udphole, call_id, c->source_socket_ids[i], c->dest_socket_ids[i]);
        udphole_forward_destroy(udphole, call_id, c->dest_socket_ids[i], c->source_socket_ids[i]);
        udphole_socket_destroy(udphole, call_id, c->source_socket_ids[i]);
        udphole_socket_destroy(udphole, call_id, c->dest_socket_ids[i]);
      }
    }
    udphole_session_destroy(udphole, call_id);
  }

  hashmap_delete(calls, c);
  free_call(c);
}

void call_handle_cancel(const char *call_id) {
  call_handle_bye(call_id);
}
