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
#include "config.h"
#include "RespModule/resp.h"
#include "AppModule/pbx/call.h"
#include "AppModule/pbx/registration.h"
#include "AppModule/pbx/trunk_reg.h"
#include "AppModule/rtp/client.h"
#include "PluginModule/plugin.h"

#define MAX_CALLS 128
#define MAX_FORKS 32

typedef struct {
  char *orig_call_id;
  char *target_ext;
  char *target_contact;
  int fd;
  int pending;
} call_fwd_t;

static call_fwd_t call_fwds[MAX_FORKS];
static size_t call_fwd_count = 0;

static call_fwd_t *call_fwd_find(const char *orig_call_id) {
  for (size_t i = 0; i < call_fwd_count; i++) {
    if (call_fwds[i].orig_call_id && strcmp(call_fwds[i].orig_call_id, orig_call_id) == 0) {
      return &call_fwds[i];
    }
  }
  return NULL;
}

static call_t *calls[MAX_CALLS];
static size_t call_count = 0;
static call_t *call_head = NULL;

static call_t *find_call(const char *call_id) {
  for (size_t i = 0; i < call_count; i++) {
    if (calls[i] && strcmp(calls[i]->call_id, call_id) == 0) {
      return calls[i];
    }
  }
  return NULL;
}

static int parse_sdp_port(const char *sdp, const char *media, int *port, char *ip, size_t ip_len) {
  const char *m = strstr(sdp, "m=");
  while (m) {
    if (strncmp(m + 2, media, strlen(media)) == 0) {
      const char *p = m + 2 + strlen(media);
      while (*p == ' ') p++;
      *port = atoi(p);

      const char *c = strstr(m, "c=IN ");
      if (c) {
        c += 5;
        while (*c == ' ') c++;
        const char *end = c;
        while (*end && *end != '\r' && *end != '\n') end++;
        size_t len = (size_t)(end - c);
        if (len >= ip_len) len = ip_len - 1;
        memcpy(ip, c, len);
        ip[len] = '\0';
      }
      return 0;
    }
    m = strstr(m + 2, "m=");
  }
  return -1;
}

static int rewrite_sdp_port(char *sdp, int new_port, const char *new_ip) {
  char *m = strstr(sdp, "m=audio ");
  if (m) {
    char *p = m + 8;
    while (*p >= '0' && *p <= '9') p++;
    char buf[256];
    snprintf(buf, sizeof(buf), "%d", new_port);
    size_t old_len = (size_t)(p - m);
    size_t new_len = strlen(buf);
    if (new_len != old_len) {
      memmove(p + (new_len - old_len), p, strlen(p) + 1);
    }
    memcpy(m, buf, new_len);
  }

  char *c = strstr(sdp, "c=IN IP4 ");
  if (c && new_ip) {
    char *p = c + 9;
    while (*p && *p != '\r' && *p != '\n') p++;
    size_t old_len = (size_t)(p - c - 9);
    size_t new_len = strlen(new_ip);
    if (new_len != old_len) {
      memmove(c + 9 + new_len, p, strlen(p) + 1);
    }
    memcpy(c + 9, new_ip, new_len);
  }

  return 0;
}

static int is_emergency(const char *number) {
  if (!global_cfg) return 0;

  resp_object *emergency = config_get_emergency();
  if (!emergency || emergency->type != RESPT_ARRAY) {
    return 0;
  }

  for (size_t i = 0; i < emergency->u.arr.n; i++) {
    if (emergency->u.arr.elem[i].type == RESPT_BULK || emergency->u.arr.elem[i].type == RESPT_SIMPLE) {
      const char *e = emergency->u.arr.elem[i].u.s;
      if (e && strcmp(e, number) == 0) {
        return 1;
      }
    }
  }
  return 0;
}

int call_route_invite(const char *from_ext, const char *to, const char *call_id, const char *sdp, char **out_sdp) {
  log_info("call_route: %s -> %s, call_id=%s", from_ext, to, call_id);

  if (is_emergency(to)) {
    log_info("call_route: emergency call %s", to);
  }

  const char *source_contact = registration_get_contact(from_ext);
  if (!source_contact) {
    log_error("call_route: extension %s not registered", from_ext);
    return -1;
  }

  extension_reg_t *dest_reg = registration_find(to);
  log_trace("call_route: dest_reg=%p for %s", dest_reg, to);
  if (dest_reg) {
    log_info("call_route: ext-to-ext %s -> %s", from_ext, to);

    if (call_count >= MAX_CALLS) {
      log_error("call_route: max calls reached");
      return -1;
    }

    call_t *c = calloc(1, sizeof(*c));
    c->call_id = strdup(call_id);
    c->source = strdup(from_ext);
    c->destination = strdup(to);
    c->source_contact = strdup(source_contact);
    c->dest_contact = strdup(dest_reg->contact);
    c->created = time(NULL);
    c->active = 1;
  } else {
    log_warn("call_route: destination %s not registered", to);
    return -2;
  }

  char src_ip[64] = "0.0.0.0";
    int src_port = 0;
    parse_sdp_port(sdp, "audio", &src_port, src_ip, sizeof(src_ip));

    rtp_session_info_t info;
    if (rtp_client_create_session(call_id, src_ip, src_port, from_ext, &info) == 0) {
      c->source_rtp_port = info.port;
      if (info.advertise_ip) {
        strncpy(c->source_rtp_ip, info.advertise_ip, sizeof(c->source_rtp_ip) - 1);
        free(info.advertise_ip);
      } else {
        strncpy(c->source_rtp_ip, "0.0.0.0", sizeof(c->source_rtp_ip) - 1);
      }
    }

    dest_reg = registration_find(to);
    if (dest_reg && dest_reg->remote_addr.ss_family != 0) {
      char dest_ip[INET6_ADDRSTRLEN];
      int dest_port = 0;
      if (dest_reg->remote_addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&dest_reg->remote_addr;
        inet_ntop(AF_INET, &sin->sin_addr, dest_ip, sizeof(dest_ip));
        dest_port = ntohs(sin->sin_port);
      } else if (dest_reg->remote_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dest_reg->remote_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, dest_ip, sizeof(dest_ip));
        dest_port = ntohs(sin6->sin6_port);
      }
      rtp_session_info_t info2;
      if (rtp_client_create_session(call_id, dest_ip, dest_port, "dest", &info2) == 0) {
        c->dest_rtp_port = info2.port;
        if (info2.advertise_ip) {
          strncpy(c->dest_rtp_ip, info2.advertise_ip, sizeof(c->dest_rtp_ip) - 1);
          free(info2.advertise_ip);
        } else {
          strncpy(c->dest_rtp_ip, "0.0.0.0", sizeof(c->dest_rtp_ip) - 1);
        }
      }
    }

    calls[call_count++] = c;
    c->next = call_head;
    call_head = c;

    *out_sdp = strdup(sdp);
    rewrite_sdp_port(*out_sdp, c->dest_rtp_port, c->dest_rtp_ip[0] ? c->dest_rtp_ip : NULL);

    log_trace("call_route: built out_sdp, dest_rtp_port=%d", c->dest_rtp_port);

    extension_reg_t *reg = registration_find(to);
    log_trace("call_route: found reg=%p for %s", reg, to);
    if (reg && reg->remote_addr.ss_family != 0) {
      char dest_ip[INET6_ADDRSTRLEN];
      int dest_port = 5060;
      if (reg->remote_addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&reg->remote_addr;
        inet_ntop(AF_INET, &sin->sin_addr, dest_ip, sizeof(dest_ip));
        dest_port = ntohs(sin->sin_port);
      } else if (reg->remote_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&reg->remote_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, dest_ip, sizeof(dest_ip));
        dest_port = ntohs(sin6->sin6_port);
      }
      int fdfwd = socket(reg->remote_addr.ss_family, SOCK_DGRAM, 0);
      if (fdfwd >= 0) {
        char *fwd_sdp = strdup(sdp);
        rewrite_sdp_port(fwd_sdp, c->source_rtp_port, c->source_rtp_ip[0] ? c->source_rtp_ip : NULL);
        char inv[2048];
        int invlen = snprintf(inv, sizeof(inv),
          "INVITE sip:%s@192.168.69.87 SIP/2.0\r\n"
          "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bKupbx%llx\r\n"
          "From: <sip:pbx@192.168.69.87>;tag=%llx\r\n"
          "To: <sip:%s@192.168.69.87>\r\n"
          "Call-ID: %s-fwd\r\n"
          "CSeq: 1 INVITE\r\n"
          "Contact: <sip:pbx@192.168.69.87:5060>\r\n"
          "Content-Type: application/sdp\r\n"
          "Content-Length: %d\r\n"
          "\r\n%s",
          to, c->dest_rtp_ip, c->dest_rtp_port, (unsigned long long)time(NULL),
          (unsigned long long)time(NULL), to, call_id, (int)strlen(fwd_sdp), fwd_sdp);
        free(fwd_sdp);
        struct sockaddr_storage addr;
        memcpy(&addr, &reg->remote_addr, sizeof(addr));
        if (addr.ss_family == AF_INET) ((struct sockaddr_in *)&addr)->sin_port = htons(dest_port);
        else ((struct sockaddr_in6 *)&addr)->sin6_port = htons(dest_port);
        if (sendto(fdfwd, inv, (size_t)invlen, 0, (struct sockaddr *)&addr, addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == invlen) {
          log_info("call_route: forwarded INVITE to %s at %s:%d", to, dest_ip, dest_port);
        } else {
          log_error("call_route: failed forward: %s", strerror(errno));
        }
        close(fdfwd);
      }
    }

    return 0;
  }

  log_info("call_route: ext-to-trunk %s -> %s", from_ext, to);

  char rewritten_dest[256] = "";
  if (config_rewrite_destination("", to, rewritten_dest, sizeof(rewritten_dest)) > 0) {
    log_info("call_route: rewritten dest '%s' -> '%s'", to, rewritten_dest);
    to = rewritten_dest;
  }

  if (call_count >= MAX_CALLS) {
    log_error("call_route: max calls reached");
    return -1;
  }

  call_t *c = calloc(1, sizeof(*c));
  c->call_id = strdup(call_id);
  c->source = strdup(from_ext);
  c->destination = strdup(to);
  c->source_contact = strdup(source_contact);
  c->created = time(NULL);
  c->active = 1;

  char src_ip[64] = "0.0.0.0";
  int src_port = 0;
  parse_sdp_port(sdp, "audio", &src_port, src_ip, sizeof(src_ip));

  rtp_session_info_t info;
  if (rtp_client_create_session(call_id, src_ip, src_port, from_ext, &info) == 0) {
    c->source_rtp_port = info.port;
    if (info.advertise_ip) {
      strncpy(c->source_rtp_ip, info.advertise_ip, sizeof(c->source_rtp_ip) - 1);
      free(info.advertise_ip);
    }
  }

  calls[call_count++] = c;

  *out_sdp = strdup(sdp);
  char *advertise = config_get_rtp_advertise_addr();
  rewrite_sdp_port(*out_sdp, c->source_rtp_port, advertise);
  free(advertise);

  return 0;
}

void call_handle_bye(const char *call_id) {
  call_t *c = find_call(call_id);
  if (!c) return;

  log_info("call_handle_bye: call_id=%s", call_id);

  if (c->source_rtp_port > 0) {
    rtp_client_delete_session(call_id, c->source, NULL);
  }
  if (c->dest_rtp_port > 0) {
    rtp_client_delete_session(call_id, "dest", NULL);
  }

  for (size_t i = 0; i < call_count; i++) {
    if (calls[i] == c) {
      memmove(&calls[i], &calls[i+1], (call_count - i - 1) * sizeof(call_t*));
      call_count--;
      break;
    }
  }

  free(c->call_id);
  free(c->source);
  free(c->destination);
  free(c->source_contact);
  free(c->dest_contact);
  free(c);
}

void call_cleanup(void) {
  time_t now = time(NULL);
  for (size_t i = call_count; i > 0; i--) {
    size_t idx = i - 1;
    call_t *c = calls[idx];
    if (c && c->active && c->created > 0 && now - c->created > 3600) {
      log_info("call_cleanup: removing stale call %s", c->call_id);
      call_handle_bye(c->call_id);
    }
  }
}

call_t *call_first(void) {
  return call_head;
}

call_t *call_find(const char *call_id) {
  return find_call(call_id);
}
