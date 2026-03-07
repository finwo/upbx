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
#include "common/hexdump.h"
#include "domain/pbx/registration.h"
#include "domain/pbx/sip/sdp_parse.h"
#include "domain/pbx/sip/sip_message.h"
#include "domain/pbx/sip/sip_proto.h"
#include "domain/pbx/sip/udphole_client.h"
#include "finwo/mindex.h"
#include "rxi/log.h"

#define CALL_TIMEOUT_SEC 3600
#define RING_TIMEOUT_SEC 60

extern int *sip_fds;

extern void sip_transport_udp_set_fds(int *fds);

static struct mindex_t *calls = NULL;

static int call_route_invite_internal(const char *from_ext, const char *to_ext, const char *call_id, const char *from_tag,
                       const char *sdp, size_t sdp_len, char **out_sdp,
                       size_t *out_sdp_len, char **out_dest_sdp, size_t *out_dest_sdp_len);

static void call_handle_bye_internal(const char *call_id, const char *sender_ext);

static void call_handle_cancel_internal(const char *call_id);

static int call_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  const call_t *ca = a;
  const call_t *cb = b;
  return strcmp(ca->call_id, cb->call_id);
}

static const call_t *find_call(const char *call_id) {
  if (!calls || !call_id) return NULL;
  call_t key = {.call_id = (char *)call_id};
  return mindex_get(calls, &key);
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

static void free_call_wrapper(void *item, void *udata) {
  (void)udata;
  free_call(item);
}

void call_init(void) {
  if (calls) return;
  calls = mindex_init(call_compare, free_call_wrapper, NULL);
}

const call_t *call_find(const char *call_id) {
  return find_call(call_id);
}

static int find_socket_by_family(int *sock_array, sa_family_t family) {
  if (!sock_array || sock_array[0] == 0) return -1;
  for (int i = 1; i <= sock_array[0]; i++) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(sock_array[i], (struct sockaddr *)&addr, &addrlen) == 0) {
      if (addr.ss_family == family) {
        return sock_array[i];
      }
    }
  }
  return -1;
}

char *call_handle_invite(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
) {
  (void)remote_addr;
  (void)listen_fd;

  if (!msg || !sip_is_request(msg) || !response_len) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len, NULL);
  }

  char from_ext[64] = {0};
  char to_ext[64] = {0};
  char call_id[256] = {0};
  char from_tag[64] = {0};

  sip_header_uri_extract_user(msg, "From", from_ext, sizeof(from_ext));
  sip_header_uri_extract_user(msg, "To", to_ext, sizeof(to_ext));
  sip_message_header_copy(msg, "Call-ID", call_id, sizeof(call_id));

  const char *from_header = sip_message_header_get(msg, "From", NULL);
  if (from_header) {
    const char *tag = strstr(from_header, ";tag=");
    if (tag) {
      tag += 5;
      const char *end = tag;
      while (*end && *end != ';' && *end != '>' && *end != '\r' && *end != '\n') end++;
      size_t tag_len = (size_t)(end - tag);
      if (tag_len < sizeof(from_tag)) {
        memcpy(from_tag, tag, tag_len);
        from_tag[tag_len] = '\0';
      }
    }
  }

  if (!from_ext[0] || !to_ext[0] || !call_id[0] || !from_tag[0]) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len, NULL);
  }

  if (!registration) {
    log_error("call_handle_invite: INVITE from unregistered source");
    return sip_proto_build_response(msg, 403, "Forbidden", NULL, NULL, 0, response_len, NULL);
  }

  if (registration_is_pattern(registration->number)) {
    if (!registration_match_pattern(registration->number, from_ext)) {
      log_error("call_handle_invite: INVITE from %s does not match pattern %s", from_ext, registration->number);
      return sip_proto_build_response(msg, 403, "Forbidden", NULL, NULL, 0, response_len, NULL);
    }
  } else {
    if (strcmp(from_ext, registration->number) != 0) {
      log_error("call_handle_invite: INVITE from %s does not match registered %s", from_ext, registration->number);
      return sip_proto_build_response(msg, 403, "Forbidden", NULL, NULL, 0, response_len, NULL);
    }
  }

  const char *sdp = msg->body;
  size_t sdp_len = msg->body_len;

  char *out_sdp = NULL;
  size_t out_sdp_len = 0;
  char *out_dest_sdp = NULL;
  size_t out_dest_sdp_len = 0;

  int r = call_route_invite_internal(from_ext, to_ext, call_id, from_tag, sdp, sdp_len, &out_sdp, &out_sdp_len, &out_dest_sdp, &out_dest_sdp_len);

  if (r == -1) {
    return sip_proto_build_response(msg, 403, "Forbidden", NULL, NULL, 0, response_len, NULL);
  } else if (r == -2) {
    return sip_proto_build_response(msg, 404, "Not Found", NULL, NULL, 0, response_len, NULL);
  }

  call_t *c = find_call(call_id);
  if (!c) {
    free(out_sdp);
    free(out_dest_sdp);
    return sip_proto_build_response(msg, 480, "Temporarily Unavailable", NULL, NULL, 0, response_len, NULL);
  }

  registration_t *dest_reg_check = registration_find(c->dest_ext);
  if (!dest_reg_check || !dest_reg_check->pbx_addr) {
    log_error("call_handle_invite: destination %s has no pbx_addr", c->dest_ext ? c->dest_ext : "(unknown)");
    free(out_sdp);
    free(out_dest_sdp);
    return sip_proto_build_response(msg, 480, "Temporarily Unavailable", NULL, NULL, 0, response_len, NULL);
  }

  char *resp = sip_proto_build_response(msg, 100, "Trying", NULL, out_sdp, out_sdp_len, response_len, NULL);
  free(out_sdp);

  log_trace("call_handle_invite: resp=%p, out_dest_sdp=%p", (void*)resp, (void*)out_dest_sdp);

  if (resp && out_dest_sdp) {
    call_t *c = find_call(call_id);
    log_trace("call_handle_invite: c=%p, dest_addr.family=%d", (void*)c, c ? c->dest_addr.ss_family : 0);

    if (c) {
      log_trace("call_handle_invite: have call, continuing");
      char dest_contact_host[256] = {0};
      fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
      int dest_contact_port = 5060;
      fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);

      log_trace("call_handle_invite: dest_contact=%s", c->dest_contact ? c->dest_contact : "(null)");
      if (c->dest_contact && c->dest_contact[0]) {
        fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
        const char *at = strchr(c->dest_contact, '@');
        fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
        if (at) {
          fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
          const char *host_start = at + 1;
          fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
          const char *colon = strchr(host_start, ':');
          fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
          if (colon) {
            fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            size_t host_len = (size_t)(colon - host_start);
            fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            if (host_len < sizeof(dest_contact_host)) {
              fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
              memcpy(dest_contact_host, host_start, host_len);
              fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
              dest_contact_host[host_len] = '\0';
              fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            }
            fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            dest_contact_port = atoi(colon + 1);
            fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
          } else {
            fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            size_t host_len = strlen(host_start);
            fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            if (host_len < sizeof(dest_contact_host)) {
              fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
              memcpy(dest_contact_host, host_start, host_len);
              fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
              dest_contact_host[host_len] = '\0';
              fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
            }
          }
        }
      }

      log_trace("call_handle_invite: after contact parse, dest_contact_host=%s, port=%d", dest_contact_host, dest_contact_port);

      if (!dest_contact_host[0]) {
        log_trace("call_handle_invite: no contact host, using dest_addr");
        if (c->dest_addr.ss_family == AF_INET) {
          fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
          struct sockaddr_in *sin = (struct sockaddr_in *)&c->dest_addr;
          inet_ntop(AF_INET, &sin->sin_addr, dest_contact_host, sizeof(dest_contact_host));
          dest_contact_port = ntohs(sin->sin_port);
        } else if (c->dest_addr.ss_family == AF_INET6) {
          fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
          struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c->dest_addr;
          inet_ntop(AF_INET6, &sin6->sin6_addr, dest_contact_host, sizeof(dest_contact_host));
          dest_contact_port = ntohs(sin6->sin6_port);
        }
      }

      log_trace("call_handle_invite: final dest_contact_host=%s, port=%d", dest_contact_host, dest_contact_port);

      char pbx_addr[256] = "127.0.0.1";
      registration_t *dest_reg = registration_find(c->dest_ext);
      log_trace("call_handle_invite: dest_reg=%p, dest_ext=%s", (void*)dest_reg, c->dest_ext ? c->dest_ext : "(null)");
      if (dest_reg && dest_reg->pbx_addr) {
        strncpy(pbx_addr, dest_reg->pbx_addr, sizeof(pbx_addr) - 1);
        pbx_addr[sizeof(pbx_addr) - 1] = '\0';
        log_trace("call_handle_invite: using dest_reg->pbx_addr=%s", pbx_addr);
      } else {
        log_trace("call_handle_invite: NO dest_reg or NO pbx_addr, using fallback=%s", pbx_addr);
      }

      char from_header[256];
      snprintf(from_header, sizeof(from_header), "<sip:%s@%s>;tag=%s", from_ext, pbx_addr, from_tag);
      char to_header[256];
      snprintf(to_header, sizeof(to_header), "<sip:%s@%s>", to_ext, pbx_addr);

      char request_uri[256];
      snprintf(request_uri, sizeof(request_uri), "sip:%s@%s", to_ext, dest_contact_host);

      log_trace("call_handle_invite: building INVITE to %s:%d via %s", dest_contact_host, dest_contact_port, pbx_addr);

      char *inv = sip_proto_build_request(
        "INVITE",
        request_uri,
        pbx_addr,
        from_header,
        to_header,
        call_id,
        "1 INVITE",
        NULL,
        "application/sdp",
        out_dest_sdp,
        out_dest_sdp_len,
        &out_dest_sdp_len
      );
      free(out_dest_sdp);

      log_trace("call_handle_invite: inv=%p, sip_fds=%p", (void*)inv, (void*)sip_fds);
      if (inv && sip_fds) {
        log_trace("call_handle_invite: have inv and sip_fds, looking for socket");
        int send_fd = find_socket_by_family(sip_fds, c->dest_addr.ss_family);
        log_trace("call_handle_invite: send_fd=%d", send_fd);
        if (send_fd >= 0) {
          log_trace("call_handle_invite: sending INVITE to %s:%d", dest_contact_host, dest_contact_port);
          log_hexdump_trace(inv, out_dest_sdp_len);
          socklen_t dst_len = (c->dest_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
          sendto(send_fd, inv, out_dest_sdp_len, 0, (struct sockaddr *)&c->dest_addr, dst_len);
        }
        free(inv);
      } else {
        log_trace("call_handle_invite: NOT sending - inv=%p, sip_fds=%p", (void*)inv, (void*)sip_fds);
      }
    } else {
      log_trace("call_handle_invite: NO call found");
    }
  } else {
    log_trace("call_handle_invite: NOT sending - resp=%p, out_dest_sdp=%p", (void*)resp, (void*)out_dest_sdp);
  }

  return resp;
}

char *call_handle_bye(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
) {
  (void)registration;
  (void)listen_fd;

  if (!msg || !response_len) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len, NULL);
  }

  char call_id[256] = {0};
  sip_message_header_copy(msg, "Call-ID", call_id, sizeof(call_id));

  if (!call_id[0]) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len, NULL);
  }

  const call_t *c = find_call(call_id);
  if (!c) {
    return sip_proto_build_response(msg, 200, "OK", NULL, NULL, 0, response_len, NULL);
  }

  const char *sender_ext = NULL;
  if (remote_addr->ss_family == AF_INET && c->source_addr.ss_family == AF_INET) {
    struct sockaddr_in *src = (struct sockaddr_in *)remote_addr;
    struct sockaddr_in *call_src = (struct sockaddr_in *)&c->source_addr;
    if (src->sin_addr.s_addr == call_src->sin_addr.s_addr) {
      sender_ext = c->source_ext;
    }
  } else if (remote_addr->ss_family == AF_INET6 && c->source_addr.ss_family == AF_INET6) {
    struct sockaddr_in6 *src = (struct sockaddr_in6 *)remote_addr;
    struct sockaddr_in6 *call_src = (struct sockaddr_in6 *)&c->source_addr;
    if (memcmp(&src->sin6_addr, &call_src->sin6_addr, sizeof(src->sin6_addr)) == 0) {
      sender_ext = c->source_ext;
    }
  }

  if (!sender_ext) {
    if (remote_addr->ss_family == AF_INET && c->dest_addr.ss_family == AF_INET) {
      struct sockaddr_in *src = (struct sockaddr_in *)remote_addr;
      struct sockaddr_in *call_dest = (struct sockaddr_in *)&c->dest_addr;
      if (src->sin_addr.s_addr == call_dest->sin_addr.s_addr) {
        sender_ext = c->dest_ext;
      }
    } else if (remote_addr->ss_family == AF_INET6 && c->dest_addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *src = (struct sockaddr_in6 *)remote_addr;
      struct sockaddr_in6 *call_dest = (struct sockaddr_in6 *)&c->dest_addr;
      if (memcmp(&src->sin6_addr, &call_dest->sin6_addr, sizeof(src->sin6_addr)) == 0) {
        sender_ext = c->dest_ext;
      }
    }
  }

  call_handle_bye_internal(call_id, sender_ext);

  return sip_proto_build_response(msg, 200, "OK", NULL, NULL, 0, response_len, NULL);
}

char *call_handle_cancel(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
) {
  (void)registration;
  (void)listen_fd;

  if (!msg || !response_len) {
    return sip_proto_build_response(msg, 400, "Bad Request", NULL, NULL, 0, response_len, NULL);
  }

  char call_id[256] = {0};
  sip_message_header_copy(msg, "Call-ID", call_id, sizeof(call_id));

  if (call_id[0]) {
    char src_ext[64] = {0};
    sip_header_uri_extract_user(msg, "From", src_ext, sizeof(src_ext));

    const call_t *c = find_call(call_id);
    if (c) {
      int authorized = (strcmp(src_ext, c->source_ext) == 0 || strcmp(src_ext, c->dest_ext) == 0);
      if (authorized) {
        call_handle_cancel_internal(call_id);
      }
    }
  }

  return sip_proto_build_response(msg, 200, "OK", NULL, NULL, 0, response_len, NULL);
}

char *call_handle_response(
  sip_message_t *msg,
  const struct sockaddr_storage *remote_addr,
  registration_t *registration,
  int listen_fd,
  size_t *response_len
) {
  (void)remote_addr;
  (void)registration;
  (void)listen_fd;

  if (!msg || !response_len) {
    return NULL;
  }

  char call_id[256] = {0};
  sip_message_header_copy(msg, "Call-ID", call_id, sizeof(call_id));

  if (!call_id[0]) {
    return NULL;
  }

  const call_t *c = find_call(call_id);
  if (!c) {
    return NULL;
  }

  int status_code = msg->status_code;
  log_trace("call_handle_response: forwarding SIP response %d for call %s", status_code, call_id);

  char pbx_addr[256] = "127.0.0.1";
  registration_t *src_reg = registration_find(c->source_ext);
  if (src_reg && src_reg->pbx_addr) {
    strncpy(pbx_addr, src_reg->pbx_addr, sizeof(pbx_addr) - 1);
    pbx_addr[sizeof(pbx_addr) - 1] = '\0';
  }

  char via_header[300];
  snprintf(via_header, sizeof(via_header), "SIP/2.0/UDP %s", pbx_addr);

  size_t fwd_len = 0;
  char *fwd_resp = sip_proto_build_response(
    msg,
    status_code,
    msg->reason,
    NULL,
    msg->body,
    msg->body_len,
    &fwd_len,
    via_header
  );

  if (fwd_resp && sip_fds) {
    int send_fd = find_socket_by_family(sip_fds, c->source_addr.ss_family);
    if (send_fd >= 0) {
      socklen_t dst_len = (c->source_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
      sendto(send_fd, fwd_resp, fwd_len, 0, (struct sockaddr *)&c->source_addr, dst_len);
    }
    free(fwd_resp);
  }

  return NULL;
}

int call_route_invite_internal(const char *from_ext, const char *to_ext, const char *call_id, const char *from_tag,
                       const char *sdp, size_t sdp_len, char **out_sdp,
                       size_t *out_sdp_len, char **out_dest_sdp, size_t *out_dest_sdp_len) {
  log_info("call: %s -> %s, call_id=%s, from_tag=%s", from_ext, to_ext, call_id, from_tag);

  registration_t *source_reg = registration_find(from_ext);
  if (!source_reg) {
    log_error("call: source extension %s not registered", from_ext);
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

  for (size_t i = 0; i < n_source_media; i++) {
    if (source_info[i].advertise_ip && source_info[i].advertise_ip[0]) {
      strncpy(c->source_rtp_ip[i], source_info[i].advertise_ip, sizeof(c->source_rtp_ip[i]) - 1);
    } else if (source_reg->pbx_addr) {
      strncpy(c->source_rtp_ip[i], source_reg->pbx_addr, sizeof(c->source_rtp_ip[i]) - 1);
    }
    c->source_rtp_ip[i][sizeof(c->source_rtp_ip[i]) - 1] = '\0';
    c->source_rtp_port[i] = source_info[i].port;
    c->source_socket_ids[i] = source_socket_ids[i];

    if (dest_info[i].advertise_ip && dest_info[i].advertise_ip[0]) {
      strncpy(c->dest_rtp_ip[i], dest_info[i].advertise_ip, sizeof(c->dest_rtp_ip[i]) - 1);
    } else if (dest_reg->pbx_addr) {
      strncpy(c->dest_rtp_ip[i], dest_reg->pbx_addr, sizeof(c->dest_rtp_ip[i]) - 1);
    }
    c->dest_rtp_ip[i][sizeof(c->dest_rtp_ip[i]) - 1] = '\0';
    c->dest_rtp_port[i] = dest_info[i].port;
    c->dest_socket_ids[i] = dest_socket_ids[i];

    free(source_info[i].advertise_ip);
    free(dest_info[i].advertise_ip);
  }

  mindex_set(calls, c);

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

  int len = sdp_rewrite_all_media(sdp, sdp_len, c->source_rtp_ip, c->source_rtp_port, (int)n_source_media, *out_sdp, 4096);
  log_trace("call_route_invite: sdp_rewrite source: port=%d, len=%d", c->source_rtp_port[0], len);
  if (len < 0) {
    free(*out_sdp);
    free(*out_dest_sdp);
    *out_sdp = NULL;
    *out_dest_sdp = NULL;
    free_call(c);
    return -1;
  }
  *out_sdp_len = (size_t)len;

  len = sdp_rewrite_all_media(sdp, sdp_len, c->dest_rtp_ip, c->dest_rtp_port, (int)n_source_media, *out_dest_sdp, 4096);
  log_trace("call_route_invite: sdp_rewrite dest: port=%d, len=%d", c->dest_rtp_port[0], len);
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

void call_handle_bye_internal(const char *call_id, const char *sender_ext) {
  const call_t *c = find_call(call_id);
  if (!c) {
    log_warn("call_bye: call not found: %s", call_id);
    return;
  }

  log_info("call_bye: call_id=%s", call_id);

  const char *pbx_addr = "127.0.0.1";
  const char *recipient_ext = NULL;
  const struct sockaddr_storage *recipient_addr = NULL;

  if (sender_ext && c->source_ext && strcmp(sender_ext, c->source_ext) == 0) {
    recipient_ext = c->dest_ext;
    recipient_addr = &c->dest_addr;
  } else if (sender_ext && c->dest_ext && strcmp(sender_ext, c->dest_ext) == 0) {
    recipient_ext = c->source_ext;
    recipient_addr = &c->source_addr;
    registration_t *sender_reg = registration_find(c->dest_ext);
    if (sender_reg && sender_reg->pbx_addr) {
      pbx_addr = sender_reg->pbx_addr;
    }
  }

  if (recipient_ext && recipient_addr) {
    char dest_host[INET6_ADDRSTRLEN] = {0};
    int dest_port = 5060;

    if (recipient_addr->ss_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)recipient_addr;
      inet_ntop(AF_INET, &sin->sin_addr, dest_host, sizeof(dest_host));
      dest_port = ntohs(sin->sin_port);
    } else if (recipient_addr->ss_family == AF_INET6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)recipient_addr;
      inet_ntop(AF_INET6, &sin6->sin6_addr, dest_host, sizeof(dest_host));
      dest_port = ntohs(sin6->sin6_port);
    }

    char from_header[256];
    snprintf(from_header, sizeof(from_header), "<sip:%s@%s>;tag=%s", sender_ext ? sender_ext : "", pbx_addr, c->from_tag ? c->from_tag : "");
    char to_header[256];
    snprintf(to_header, sizeof(to_header), "<sip:%s@%s>", recipient_ext, pbx_addr);

    size_t bye_len = 0;
    char *bye = sip_proto_build_request(
      "BYE",
      dest_host,
      pbx_addr,
      from_header,
      to_header,
      call_id,
      "1 BYE",
      NULL,
      NULL,
      NULL,
      0,
      &bye_len
    );

    if (bye && bye_len > 0) {
      int send_fd = socket(recipient_addr->ss_family, SOCK_DGRAM, 0);
      if (send_fd >= 0) {
        socklen_t dst_len = (recipient_addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        ssize_t sent = sendto(send_fd, bye, bye_len, 0, (const struct sockaddr *)recipient_addr, dst_len);
        if (sent > 0) {
          log_info("call_bye: forwarded BYE to %s (%s:%d)", recipient_ext, dest_host, dest_port);
        } else {
          log_error("call_bye: failed to forward BYE to %s: %s", recipient_ext, strerror(errno));
        }
        close(send_fd);
      }
      free(bye);
    }
  }

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

  call_t key = {.call_id = (char*)call_id};
  mindex_delete(calls, &key);
}

void call_handle_cancel_internal(const char *call_id) {
  call_handle_bye_internal(call_id, NULL);
}
