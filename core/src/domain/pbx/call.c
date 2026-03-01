#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include "rxi/log.h"
#include "tidwall/hashmap.h"
#include "domain/pbx/call.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sdp_parse.h"
#include "domain/pbx/sip/udphole_client.h"

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

static call_t *find_call(const char *call_id) {
  if (!calls || !call_id) return NULL;
  call_t key = { .call_id = (char *)call_id };
  return hashmap_get(calls, &key);
}

static const char *get_advertise_ip(void) {
  const char *adv = udphole_get_advertise_addr();
  if (adv && adv[0]) return adv;
  return NULL;
}

static void free_call(call_t *c) {
  if (!c) return;
  free(c->call_id);
  free(c->source_ext);
  free(c->dest_ext);
  free(c->source_contact);
  free(c->dest_contact);
  free(c->from_tag);
  free(c->to_tag);
  free(c);
}

void call_init(void) {
  if (calls) return;
  calls = hashmap_new(sizeof(call_t), 64, 0, 0, call_hash, call_compare, NULL, NULL);
}

call_t *call_find(const char *call_id) {
  return find_call(call_id);
}

static int parse_sdp_port(const char *sdp, size_t sdp_len, int *port, char *ip, size_t ip_len) {
  sdp_media_t media[SDP_MAX_MEDIA];
  size_t n_out = 0;

  if (sdp_parse_media(sdp, sdp_len, media, SDP_MAX_MEDIA, &n_out) != 0 || n_out == 0) {
    return -1;
  }

  if (port) *port = media[0].port;
  if (ip && ip_len > 0) {
    strncpy(ip, media[0].ip, ip_len - 1);
    ip[ip_len - 1] = '\0';
  }

  return 0;
}

int call_route_invite(const char *from_ext, const char *to_ext, const char *call_id,
                      const char *from_tag, const char *sdp, size_t sdp_len,
                      const char *source_ip, int source_port,
                      char **out_sdp, size_t *out_sdp_len) {
  log_info("call: %s -> %s, call_id=%s, from_tag=%s", from_ext, to_ext, call_id, from_tag);

  registration_t *source_reg = registration_find(from_ext);
  if (!source_reg) {
    log_error("call: source extension %s not registered", from_ext);
    return -1;
  }

  char source_reg_ip[INET6_ADDRSTRLEN] = {0};
  int source_reg_port = 0;
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
    log_error("call: source IP mismatch: expected %s:%d, got %s:%d",
              source_reg_ip, source_reg_port, source_ip, source_port);
    return -1;
  }

  registration_t *dest_reg = registration_find(to_ext);
  if (!dest_reg) {
    log_error("call: destination extension %s not registered", to_ext);
    return -2;
  }

  udphole_client_t *udphole = udphole_get_client();
  if (!udphole) {
    log_error("call: udphole not initialized");
    return -1;
  }

  if (udphole_session_create(udphole, call_id, CALL_TIMEOUT_SEC) != 0) {
    log_error("call: failed to create udphole session");
    return -1;
  }

  udphole_socket_info_t source_info;
  if (udphole_socket_create_listen(udphole, call_id, from_tag, &source_info) != 0) {
    log_error("call: failed to create source socket");
    udphole_session_destroy(udphole, call_id);
    return -1;
  }

  char dest_tag[] = "dest";
  udphole_socket_info_t dest_info;
  if (udphole_socket_create_listen(udphole, call_id, dest_tag, &dest_info) != 0) {
    log_error("call: failed to create dest socket");
    udphole_socket_destroy(udphole, call_id, from_tag);
    udphole_session_destroy(udphole, call_id);
    return -1;
  }

  if (udphole_forward_create(udphole, call_id, from_tag, dest_tag) != 0) {
    log_error("call: failed to create forward source->dest");
    udphole_socket_destroy(udphole, call_id, dest_tag);
    udphole_socket_destroy(udphole, call_id, from_tag);
    udphole_session_destroy(udphole, call_id);
    return -1;
  }

  if (udphole_forward_create(udphole, call_id, dest_tag, from_tag) != 0) {
    log_error("call: failed to create forward dest->source");
    udphole_forward_destroy(udphole, call_id, from_tag, dest_tag);
    udphole_socket_destroy(udphole, call_id, dest_tag);
    udphole_socket_destroy(udphole, call_id, from_tag);
    udphole_session_destroy(udphole, call_id);
    return -1;
  }

  call_t *c = calloc(1, sizeof(*c));
  c->call_id = strdup(call_id);
  c->source_ext = strdup(from_ext);
  c->dest_ext = strdup(to_ext);
  c->source_contact = strdup(source_reg->contact ? source_reg->contact : "");
  c->dest_contact = strdup(dest_reg->contact ? dest_reg->contact : "");
  memcpy(&c->source_addr, &source_reg->remote_addr, sizeof(c->source_addr));
  memcpy(&c->dest_addr, &dest_reg->remote_addr, sizeof(c->dest_addr));
  c->from_tag = strdup(from_tag);
  c->to_tag = strdup(dest_tag);
  c->created = time(NULL);

  if (source_info.advertise_ip && source_info.advertise_ip[0]) {
    strncpy(c->source_rtp_ip, source_info.advertise_ip, sizeof(c->source_rtp_ip) - 1);
  } else {
    const char *adv = get_advertise_ip();
    if (adv) {
      strncpy(c->source_rtp_ip, adv, sizeof(c->source_rtp_ip) - 1);
    }
  }
  c->source_rtp_port = source_info.port;

  if (dest_info.advertise_ip && dest_info.advertise_ip[0]) {
    strncpy(c->dest_rtp_ip, dest_info.advertise_ip, sizeof(c->dest_rtp_ip) - 1);
  } else {
    const char *adv = get_advertise_ip();
    if (adv) {
      strncpy(c->dest_rtp_ip, adv, sizeof(c->dest_rtp_ip) - 1);
    }
  }
  c->dest_rtp_port = dest_info.port;

  free(source_info.advertise_ip);
  free(dest_info.advertise_ip);

  hashmap_set(calls, c);

  char sdp_ip[64] = {0};
  int sdp_port = 0;
  parse_sdp_port(sdp, sdp_len, &sdp_port, sdp_ip, sizeof(sdp_ip));

  *out_sdp = malloc(4096);
  if (!*out_sdp) {
    free_call(c);
    return -1;
  }

  int len = sdp_rewrite_addr(sdp, sdp_len,
                              c->dest_rtp_ip[0] ? c->dest_rtp_ip : "0.0.0.0",
                              c->dest_rtp_port,
                              *out_sdp, 4096);
  if (len < 0) {
    free(*out_sdp);
    *out_sdp = NULL;
    free_call(c);
    return -1;
  }

  *out_sdp_len = (size_t)len;

  log_info("call: session created: source_rtp=%s:%d, dest_rtp=%s:%d",
           c->source_rtp_ip, c->source_rtp_port,
           c->dest_rtp_ip, c->dest_rtp_port);

  return 0;
}

void call_handle_bye(const char *call_id) {
  call_t *c = find_call(call_id);
  if (!c) {
    log_warn("call_bye: call not found: %s", call_id);
    return;
  }

  log_info("call_bye: call_id=%s", call_id);

  udphole_client_t *udphole = udphole_get_client();
  if (udphole) {
    udphole_forward_destroy(udphole, call_id, c->from_tag, c->to_tag);
    udphole_forward_destroy(udphole, call_id, c->to_tag, c->from_tag);
    udphole_socket_destroy(udphole, call_id, c->from_tag);
    udphole_socket_destroy(udphole, call_id, c->to_tag);
    udphole_session_destroy(udphole, call_id);
  }

  hashmap_delete(calls, c);
  free_call(c);
}

void call_handle_cancel(const char *call_id) {
  call_handle_bye(call_id);
}
