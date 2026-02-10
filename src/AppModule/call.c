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
#include "rxi/log.h"

#define RTP_BUF_SIZE 1520

/* ---- Linked list of active calls ---- */

static call_t *call_list = NULL;

/* Track last-used port so we rotate through the range. */
static int prev_port = 0;

/* Pre-remove callback (e.g. for plugin CALL.HANGUP notifications). */
static call_pre_remove_cb pre_remove_cb = NULL;

void call_set_pre_remove_callback(call_pre_remove_cb cb) {
  pre_remove_cb = cb;
}

/* ---- Helpers ---- */

static void party_free(call_party_t *p) {
  free(p->id);   p->id  = NULL;
  free(p->tag);  p->tag = NULL;
}

static void rtp_close(int *sock) {
  if (*sock > 0) { close(*sock); *sock = 0; }
}

/* ---- Lifecycle ---- */

call_t *call_create(const char *call_id) {
  call_t *c = calloc(1, sizeof(*c));
  if (!c) return NULL;
  if (call_id)
    snprintf(c->call_id, sizeof(c->call_id), "%s", call_id);
  c->created_at    = time(NULL);
  c->rtp_active_at = c->created_at;
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
  free(call->original_invite);
  free(call->caller_via);
  free(call->source_str);
  free(call->dest_str);
  free(call->direction);
  free(call);
}

call_t *call_first(void) { return call_list; }

/* ---- RTP port allocation ---- */

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

/* Check if a port is already in use by any call's RTP sockets. */
static int port_in_use(struct in_addr ip, int port) {
  for (call_t *c = call_list; c; c = c->next) {
    if (c->rtp_sock_a > 0 && c->rtp_port_a == port) return 1;
    if (c->rtp_sock_b > 0 && c->rtp_port_b == port) return 1;
  }
  return 0;
}

int call_rtp_alloc_port(struct in_addr local_ip, int port_low, int port_high,
                        int *sock_out, int *port_out) {
  int range = port_high - port_low + 1;
  if (range <= 0) return -1;
  if (prev_port < port_low || prev_port > port_high)
    prev_port = port_high;

  for (int k = 0; k < range; k++) {
    int p = (prev_port - port_low + 2 + k) % range + port_low;
    p &= ~1;  /* force even */
    if (p < port_low) p += 2;
    if (p > port_high) continue;
    if (port_in_use(local_ip, p)) continue;

    int s = bind_udp(local_ip, p);
    if (s < 0) continue;
    prev_port  = p;
    *sock_out  = s;
    *port_out  = p;
    return 0;
  }
  return -1;
}

/* ---- select() integration ---- */

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
      log_info("RTP: call %.32s A->B=%lu B->A=%lu pkts",
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
      log_info("call: aging idle call %.32s (no RTP for %ds)",
               c->call_id, timeout_sec);
      call_remove(c);
    }
    c = next;
  }
}
