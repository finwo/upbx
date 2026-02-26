/*
 * Unified call state and RTP relay.
 *
 * Each call_t owns two UDP sockets (one per party). RTP forwarding is:
 *   receive on rtp_sock_a → sendto(rtp_remote_b)
 *   receive on rtp_sock_b → sendto(rtp_remote_a)
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

#define RTP_BUF_SIZE 1520

/* Linked list of active calls */

static call_t *call_list = NULL;

/* Pre-remove callback (e.g. for plugin CALL.HANGUP notifications). */
static call_pre_remove_cb pre_remove_cb = NULL;

void call_set_pre_remove_callback(call_pre_remove_cb cb) {
  pre_remove_cb = cb;
}

/* Helpers */

static void party_free(call_party_t *p) {
  free(p->id);   p->id  = NULL;
  free(p->tag);  p->tag = NULL;
}

static void rtp_close(int *sock) {
  if (*sock > 0) { close(*sock); *sock = 0; }
}

/* Lifecycle */

call_t *call_create(const char *call_id) {
  log_trace("call_create: %.32s", call_id ? call_id : "");
  call_t *c = calloc(1, sizeof(*c));
  if (!c) return NULL;
  if (call_id)
    snprintf(c->call_id, sizeof(c->call_id), "%s", call_id);
  c->created_at    = time(NULL);
  c->rtp_active_at = c->created_at;
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

  /* Unlink from list. */
  if (call_list == call) {
    call_list = call->next;
  } else {
    for (call_t *p = call_list; p; p = p->next) {
      if (p->next == call) { p->next = call->next; break; }
    }
  }

  /* Close RTP sockets. */
  rtp_close(&call->rtp_sock_a);
  rtp_close(&call->rtp_sock_b);

  /* Free strings. */
  party_free(&call->a);
  party_free(&call->b);
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

/* RTP port allocation */

static int bind_udp(struct in_addr ip, int port) {
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) return -1;
  int on = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_addr   = ip;
  sa.sin_port   = htons((uint16_t)port);
  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    close(sock);
    return -1;
  }
  set_socket_nonblocking(sock, 1);
  return sock;
}

int call_rtp_alloc_port(call_t *call, int side_a,
                        struct in_addr local_ip, int port_low, int port_high,
                        int *sock_out, int *port_out) {
  (void)port_low;
  (void)port_high;

  rtpp_client_t *client = rtpproxy_get_client();
  if (!client) {
    log_error("call: no rtpproxy available");
    return -1;
  }

  static int call_num = 0;
  char call_id[64];
  snprintf(call_id, sizeof(call_id), "call-%d", call_num++);
  
  int port = 0;
  char rtp_ip[64] = {0};
  int r = rtpp_update(client, call_id, "0.0.0.0", 0, call_id, NULL, NULL, &port, rtp_ip, sizeof(rtp_ip));
  if (r != 0 || port <= 0) {
    log_error("call: rtpproxy allocation failed");
    return -1;
  }

  int s = bind_udp(local_ip, port);
  if (s < 0) {
    log_error("call: failed to bind rtpproxy port %d", port);
    return -1;
  }

  *sock_out = s;
  *port_out = port;
  
  /* Store the IP to use in SDP */
  if (call) {
    char *dest_ip = call->rtp_proxy_ip_a;
    if (!side_a) dest_ip = call->rtp_proxy_ip_b;
    
    if (rtp_ip[0]) {
      strncpy(dest_ip, rtp_ip, 63);
    } else {
      const char *fallback = rtpproxy_get_fallback_ip();
      if (fallback) {
        strncpy(dest_ip, fallback, 63);
      } else {
        inet_ntop(AF_INET, &local_ip, dest_ip, 64);
      }
    }
    dest_ip[63] = '\0';
  }
  
  log_trace("call: allocated RTP port %d via rtpproxy (ip=%s)", port, 
            call ? (side_a ? call->rtp_proxy_ip_a : call->rtp_proxy_ip_b) : "n/a");
  return 0;
}

/* select() integration */

static void fd_add(int fd, fd_set *set, int *maxfd) {
  if (fd <= 0) return;
  FD_SET(fd, set);
  if (fd > *maxfd) *maxfd = fd;
}

void call_fill_rtp_fds(fd_set *read_set, int *maxfd) {
  for (call_t *c = call_list; c; c = c->next) {
    fd_add(c->rtp_sock_a, read_set, maxfd);
    fd_add(c->rtp_sock_b, read_set, maxfd);
  }
}

/* Forward one direction: read from recv_sock, sendto dst_remote via send_sock.
 * Using a separate send_sock ensures the remote party sees packets from the
 * port it was told to send to (symmetric RTP).
 * Returns 1 if a packet was forwarded, 0 otherwise. */
static int forward_rtp(int recv_sock, int send_sock,
                       struct sockaddr_in *dst_remote,
                       fd_set *read_set, time_t *active_at) {
  if (recv_sock <= 0 || !FD_ISSET(recv_sock, read_set)) return 0;
  if (dst_remote->sin_port == 0 || dst_remote->sin_addr.s_addr == 0) {
    /* Destination not yet known (e.g. waiting for 200 OK SDP); drain. */
    char buf[RTP_BUF_SIZE];
    read(recv_sock, buf, sizeof(buf));
    return 0;
  }
  char buf[RTP_BUF_SIZE];
  ssize_t n = read(recv_sock, buf, sizeof(buf));
  if (n <= 0) return 0;
  sendto(send_sock, buf, (size_t)n, 0,
         (struct sockaddr *)dst_remote, sizeof(*dst_remote));
  *active_at = time(NULL);
  return 1;
}

void call_relay_rtp(fd_set *read_set) {
  for (call_t *c = call_list; c; c = c->next) {
    /* A→B: receive from caller (sock_a), send to callee via sock_b
     *       so callee sees packets from port_b (the port it sends to). */
    if (forward_rtp(c->rtp_sock_a, c->rtp_sock_b, &c->rtp_remote_b, read_set, &c->rtp_active_at))
      c->rtp_pkts_a2b++;

    /* B→A: receive from callee (sock_b), send to caller via sock_a
     *       so caller sees packets from port_a (the port it sends to). */
    if (forward_rtp(c->rtp_sock_b, c->rtp_sock_a, &c->rtp_remote_a, read_set, &c->rtp_active_at))
      c->rtp_pkts_b2a++;

    /* Log RTP stats every 5 seconds while active. */
    time_t now = time(NULL);
    if (c->rtp_pkts_a2b + c->rtp_pkts_b2a > 0 && now - c->rtp_log_at >= 5) {
      log_trace("RTP: call %.32s A->B=%lu B->A=%lu pkts",
               c->call_id, c->rtp_pkts_a2b, c->rtp_pkts_b2a);
      c->rtp_log_at = now;
    }
  }
}

void call_age_idle(int timeout_sec) {
  time_t cutoff = time(NULL) - timeout_sec;
  call_t *c = call_list;
  while (c) {
    call_t *next = c->next;
    if (c->rtp_active_at < cutoff && c->created_at < cutoff) {
      log_debug("call: aging idle call %.32s (no RTP for %ds)",
               c->call_id, timeout_sec);
      call_remove(c);
    }
    c = next;
  }
}

void call_set_transport(call_t *call, int side_a, const char *transport) {
  if (!call || !transport) return;
  char *dest = side_a ? call->transport_a : call->transport_b;
  strncpy(dest, transport, sizeof(call->transport_a) - 1);
  dest[sizeof(call->transport_a) - 1] = '\0';
}

int call_connect_tcp_rtp(call_t *call, int side_a, const char *remote_ip, int remote_port) {
  if (!call) return -1;
  if (side_a) {
    call->rtp_tcp_conn_a = rtpproxy_connect_tcp(remote_ip, remote_port);
    return call->rtp_tcp_conn_a;
  } else {
    call->rtp_tcp_conn_b = rtpproxy_connect_tcp(remote_ip, remote_port);
    return call->rtp_tcp_conn_b;
  }
}
