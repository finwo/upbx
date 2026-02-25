/*
 * RTP Proxy: handles both UDP and TCP RTP forwarding.
 *
 * All media passes through the PBX RTP proxy; no direct peer-to-peer RTP.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "rxi/log.h"
#include "AppModule/rtpproxy.h"

#define MAX_CALLS 256

typedef struct {
  int forward_sock;
  int tcp_listen_sock;
  int tcp_conn_sock;
  struct sockaddr_in remote;
  char transport[4];
  int in_use;
} rtp_call_t;

static rtp_call_t calls[MAX_CALLS];
static int rtp_initialized;

void rtpproxy_init(void) {
  if (rtp_initialized) return;
  memset(calls, 0, sizeof(calls));
  rtp_initialized = 1;
}

void rtpproxy_cleanup(void) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (calls[i].forward_sock > 0) close(calls[i].forward_sock);
    if (calls[i].tcp_listen_sock > 0) close(calls[i].tcp_listen_sock);
    if (calls[i].tcp_conn_sock > 0) close(calls[i].tcp_conn_sock);
  }
  memset(calls, 0, sizeof(calls));
  rtp_initialized = 0;
}

int rtpproxy_alloc_udp_port(struct in_addr local_ip, int port_low, int port_high,
                             int *sock, int *port) {
  for (int p = port_low; p <= port_high; p += 2) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) continue;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = local_ip;
    addr.sin_port = htons((uint16_t)p);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      *sock = s;
      *port = p;
      return 0;
    }
    close(s);
  }
  return -1;
}

int rtpproxy_alloc_tcp_port(struct in_addr local_ip, int port_low, int port_high,
                           int *sock, int *port) {
  for (int p = port_low; p <= port_high; p += 2) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) continue;
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = local_ip;
    addr.sin_port = htons((uint16_t)p);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      if (listen(s, 1) == 0) {
        *sock = s;
        *port = p;
        return 0;
      }
    }
    close(s);
  }
  return -1;
}

int rtpproxy_connect_tcp(const char *remote_ip, int remote_port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons((uint16_t)remote_port);

  if (inet_pton(AF_INET, remote_ip, &addr.sin_addr) <= 0) {
    struct hostent *he = gethostbyname(remote_ip);
    if (!he) return -1;
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
  }

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return -1;

  int flags = fcntl(s, F_GETFL, 0);
  fcntl(s, F_SETFL, flags | O_NONBLOCK);

  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS) {
    close(s);
    return -1;
  }

  return s;
}

void rtpproxy_register_call(int forward_sock, int tcp_listen_sock, int tcp_conn_sock,
                            struct sockaddr_in *remote, const char *transport) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (!calls[i].in_use) {
      calls[i].in_use = 1;
      calls[i].forward_sock = forward_sock;
      calls[i].tcp_listen_sock = tcp_listen_sock;
      calls[i].tcp_conn_sock = tcp_conn_sock;
      if (remote) memcpy(&calls[i].remote, remote, sizeof(*remote));
      if (transport) {
        memcpy(calls[i].transport, transport, 4);
      } else {
        memcpy(calls[i].transport, "udp", 4);
      }
      return;
    }
  }
  log_error("rtpproxy: no free slots for new call");
}

void rtpproxy_unregister_call(int forward_sock, int tcp_listen_sock, int tcp_conn_sock) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (calls[i].in_use &&
        calls[i].forward_sock == forward_sock &&
        calls[i].tcp_listen_sock == tcp_listen_sock &&
        calls[i].tcp_conn_sock == tcp_conn_sock) {
      calls[i].in_use = 0;
      if (calls[i].forward_sock > 0) close(calls[i].forward_sock);
      if (calls[i].tcp_listen_sock > 0) close(calls[i].tcp_listen_sock);
      if (calls[i].tcp_conn_sock > 0) close(calls[i].tcp_conn_sock);
      calls[i].forward_sock = 0;
      calls[i].tcp_listen_sock = 0;
      calls[i].tcp_conn_sock = 0;
      return;
    }
  }
}

void rtpproxy_fill_fds(fd_set *read_set, int *maxfd) {
  for (int i = 0; i < MAX_CALLS; i++) {
    if (!calls[i].in_use) continue;
    if (calls[i].forward_sock > 0) {
      FD_SET(calls[i].forward_sock, read_set);
      if (calls[i].forward_sock > *maxfd) *maxfd = calls[i].forward_sock;
    }
    if (calls[i].tcp_listen_sock > 0) {
      FD_SET(calls[i].tcp_listen_sock, read_set);
      if (calls[i].tcp_listen_sock > *maxfd) *maxfd = calls[i].tcp_listen_sock;
    }
    if (calls[i].tcp_conn_sock > 0) {
      FD_SET(calls[i].tcp_conn_sock, read_set);
      if (calls[i].tcp_conn_sock > *maxfd) *maxfd = calls[i].tcp_conn_sock;
    }
  }
}

void rtpproxy_process(fd_set *read_set,
                      int forward_sock_a, int tcp_listen_a, int tcp_conn_a, struct sockaddr_in *remote_a,
                      int forward_sock_b, int tcp_listen_b, int tcp_conn_b, struct sockaddr_in *remote_b,
                      time_t *active_at, unsigned long *pkts_a2b, unsigned long *pkts_b2a) {
  char buf[RTP_BUF_SIZE];
  ssize_t n;

  if (forward_sock_a > 0 && FD_ISSET(forward_sock_a, read_set)) {
    n = recv(forward_sock_a, buf, sizeof(buf), 0);
    if (n > 0 && remote_b) {
      sendto(forward_sock_b, buf, n, 0, (struct sockaddr *)remote_b, sizeof(*remote_b));
      if (active_at) *active_at = time(NULL);
      if (pkts_a2b) (*pkts_a2b)++;
    }
  }

  if (forward_sock_b > 0 && FD_ISSET(forward_sock_b, read_set)) {
    n = recv(forward_sock_b, buf, sizeof(buf), 0);
    if (n > 0 && remote_a) {
      sendto(forward_sock_a, buf, n, 0, (struct sockaddr *)remote_a, sizeof(*remote_a));
      if (active_at) *active_at = time(NULL);
      if (pkts_b2a) (*pkts_b2a)++;
    }
  }

  if (tcp_listen_a > 0 && FD_ISSET(tcp_listen_a, read_set)) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(tcp_listen_a, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd > 0) {
      log_trace("rtpproxy: accepted TCP connection on listen_a");
    }
  }

  if (tcp_listen_b > 0 && FD_ISSET(tcp_listen_b, read_set)) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(tcp_listen_b, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd > 0) {
      log_trace("rtpproxy: accepted TCP connection on listen_b");
    }
  }

  if (tcp_conn_a > 0 && FD_ISSET(tcp_conn_a, read_set)) {
    n = recv(tcp_conn_a, buf, sizeof(buf), 0);
    if (n > 0 && forward_sock_b > 0 && remote_b) {
      sendto(forward_sock_b, buf, n, 0, (struct sockaddr *)remote_b, sizeof(*remote_b));
      if (active_at) *active_at = time(NULL);
      if (pkts_a2b) (*pkts_a2b)++;
    }
  }

  if (tcp_conn_b > 0 && FD_ISSET(tcp_conn_b, read_set)) {
    n = recv(tcp_conn_b, buf, sizeof(buf), 0);
    if (n > 0 && forward_sock_a > 0 && remote_a) {
      sendto(forward_sock_a, buf, n, 0, (struct sockaddr *)remote_a, sizeof(*remote_a));
      if (active_at) *active_at = time(NULL);
      if (pkts_b2a) (*pkts_b2a)++;
    }
  }
}
