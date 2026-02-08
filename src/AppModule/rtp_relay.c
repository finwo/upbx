/*
 * Built-in RTP relay (AppModule): runs as a neco coroutine; uses neco_wait_dl
 * on RTP/RTCP sockets and forwards packets between the two legs of a call.
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

#include "tidwall/neco.h"
#include "config.h"
#include "AppModule/rtp_relay.h"

#define RTP_RELAY_TABLE_SIZE  512
#define RTP_BUFFER_SIZE       1520
#define CALLID_NUM_SIZE       256
#define CALLID_HOST_SIZE      128
#define RTP_TIMEOUT_SEC       120

typedef struct {
  int rtp_rx_sock;
  int rtp_tx_sock;
  int rtp_con_rx_sock;
  int rtp_con_tx_sock;
  char callid_number[CALLID_NUM_SIZE];
  char callid_host[CALLID_HOST_SIZE];
  int direction;
  int call_direction;
  int media_stream_no;
  int cseq;
  struct in_addr local_ipaddr;
  int local_port;
  struct in_addr remote_ipaddr;
  int remote_port;
  time_t timestamp;
  int opposite_entry;
} rtp_relay_entry_t;

static rtp_relay_entry_t rtp_table[RTP_RELAY_TABLE_SIZE];
static neco_mutex rtp_mutex;
static int rtp_mutex_initialized;
static int rtp_port_low = 10000;
static int rtp_port_high = 20000;
static int rtp_prev_port = 0;
static fd_set rtp_master_fdset;
static int rtp_master_fd_max = -1;

static int compare_callid(const char *n1, const char *h1, const char *n2, const char *h2) {
  const char *a = n1 ? n1 : "";
  const char *b = n2 ? n2 : "";
  if (strcmp(a, b) != 0) return -1;
  a = h1 ? h1 : "";
  b = h2 ? h2 : "";
  return strcmp(a, b);
}

static int sockbind(struct in_addr addr, int port) {
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) return -1;
  int on = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
    close(sock);
    return -1;
  }
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr = addr;
  sa.sin_port = htons((uint16_t)port);
  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    close(sock);
    return -1;
  }
  return sock;
}

static void rtp_recreate_fdset(void) {
  FD_ZERO(&rtp_master_fdset);
  rtp_master_fd_max = -1;
  for (int i = 0; i < RTP_RELAY_TABLE_SIZE; i++) {
    if (rtp_table[i].rtp_rx_sock > 0) {
      FD_SET(rtp_table[i].rtp_rx_sock, &rtp_master_fdset);
      if (rtp_table[i].rtp_rx_sock > rtp_master_fd_max)
        rtp_master_fd_max = rtp_table[i].rtp_rx_sock;
      FD_SET(rtp_table[i].rtp_con_rx_sock, &rtp_master_fdset);
      if (rtp_table[i].rtp_con_rx_sock > rtp_master_fd_max)
        rtp_master_fd_max = rtp_table[i].rtp_con_rx_sock;
    }
  }
}

/* Find opposite leg: same callid, same call_direction, same media_stream_no, opposite direction */
static int match_socket(int idx) {
  const int dir = rtp_table[idx].direction;
  const int call_dir = rtp_table[idx].call_direction;
  const int media = rtp_table[idx].media_stream_no;
  for (int j = 0; j < RTP_RELAY_TABLE_SIZE; j++) {
    if (rtp_table[j].rtp_rx_sock <= 0) continue;
    if (compare_callid(rtp_table[idx].callid_number, rtp_table[idx].callid_host,
                       rtp_table[j].callid_number, rtp_table[j].callid_host) != 0)
      continue;
    if (rtp_table[j].call_direction != call_dir || rtp_table[j].media_stream_no != media)
      continue;
    if (rtp_table[j].direction == dir) continue; /* need opposite */
    rtp_table[idx].rtp_tx_sock = rtp_table[j].rtp_rx_sock;
    rtp_table[idx].rtp_con_tx_sock = rtp_table[j].rtp_con_rx_sock;
    rtp_table[idx].opposite_entry = j;
    rtp_table[j].opposite_entry = idx;
    return j;
  }
  return -1;
}

/* Neco coroutine: wait on relay sockets with neco_wait_dl, forward packets, age idle streams. */
void rtp_relay_coro(int argc, void *argv[]) {
  (void)argc;
  (void)argv;
  char buf[RTP_BUFFER_SIZE];
  time_t last_aging = 0;

  if (!rtp_mutex_initialized)
    return;

  for (;;) {
    int64_t deadline = neco_now() + 5000000000; /* 5 s */
    int processed = 0;

    for (int i = 0; i < RTP_RELAY_TABLE_SIZE; i++) {
      int fd1 = -1, fd2 = -1;
      neco_mutex_lock(&rtp_mutex);
      if (rtp_table[i].rtp_rx_sock <= 0) {
        neco_mutex_unlock(&rtp_mutex);
        continue;
      }
      fd1 = rtp_table[i].rtp_rx_sock;
      fd2 = rtp_table[i].rtp_con_rx_sock;
      neco_mutex_unlock(&rtp_mutex);

      int r = neco_wait_dl(fd1, NECO_WAIT_READ, deadline);
      if (r == NECO_OK) {
        neco_mutex_lock(&rtp_mutex);
        if (rtp_table[i].rtp_rx_sock == fd1 && rtp_table[i].rtp_tx_sock > 0) {
          ssize_t count = read(fd1, buf, sizeof(buf));
          if (count > 0) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr = rtp_table[i].remote_ipaddr;
            dst.sin_port = htons((uint16_t)rtp_table[i].remote_port);
            sendto(rtp_table[i].rtp_tx_sock, buf, (size_t)count, 0,
                   (struct sockaddr *)&dst, sizeof(dst));
            rtp_table[i].timestamp = time(NULL);
            if (rtp_table[i].opposite_entry >= 0)
              rtp_table[rtp_table[i].opposite_entry].timestamp = rtp_table[i].timestamp;
          }
        }
        neco_mutex_unlock(&rtp_mutex);
        processed = 1;
        break;
      }
      if (r == NECO_TIMEDOUT)
        break;

      r = neco_wait_dl(fd2, NECO_WAIT_READ, deadline);
      if (r == NECO_OK) {
        neco_mutex_lock(&rtp_mutex);
        if (rtp_table[i].rtp_con_rx_sock == fd2 && rtp_table[i].rtp_con_tx_sock > 0) {
          ssize_t count = read(fd2, buf, sizeof(buf));
          if (count > 0) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr = rtp_table[i].remote_ipaddr;
            dst.sin_port = htons((uint16_t)(rtp_table[i].remote_port + 1));
            sendto(rtp_table[i].rtp_con_tx_sock, buf, (size_t)count, 0,
                   (struct sockaddr *)&dst, sizeof(dst));
          }
        }
        neco_mutex_unlock(&rtp_mutex);
        processed = 1;
        break;
      }
      if (r == NECO_TIMEDOUT)
        break;
    }

    /* Age out idle streams */
    time_t now = time(NULL);
    if (now > last_aging && !processed) {
      last_aging = now + 10;
      neco_mutex_lock(&rtp_mutex);
      for (int i = 0; i < RTP_RELAY_TABLE_SIZE; i++) {
        if (rtp_table[i].rtp_rx_sock <= 0) continue;
        if (rtp_table[i].timestamp + RTP_TIMEOUT_SEC >= now) continue;
        if (rtp_table[i].rtp_rx_sock > 0) close(rtp_table[i].rtp_rx_sock);
        if (rtp_table[i].rtp_con_rx_sock > 0) close(rtp_table[i].rtp_con_rx_sock);
        if (rtp_table[i].opposite_entry >= 0)
          rtp_table[rtp_table[i].opposite_entry].opposite_entry = -1;
        memset(&rtp_table[i], 0, sizeof(rtp_table[i]));
      }
      rtp_recreate_fdset();
      neco_mutex_unlock(&rtp_mutex);
    }
  }
}

int rtp_relay_init(struct upbx_config *cfg) {
  if (!cfg) return -1;
  rtp_port_low = cfg->rtp_port_low;
  rtp_port_high = cfg->rtp_port_high;
  if (rtp_port_low <= 0 || rtp_port_high < rtp_port_low) {
    rtp_port_low = 10000;
    rtp_port_high = 20000;
  }
  rtp_prev_port = rtp_port_high;
  memset(rtp_table, 0, sizeof(rtp_table));
  FD_ZERO(&rtp_master_fdset);
  if (!rtp_mutex_initialized) {
    if (neco_mutex_init(&rtp_mutex) != 0)
      return -1;
    rtp_mutex_initialized = 1;
  }
  return 0;
}

int rtp_relay_start_fwd(struct upbx_config *cfg,
  const char *call_id_number, const char *call_id_host,
  int rtp_direction, int call_direction, int media_stream_no,
  struct in_addr local_ip, int *local_port,
  struct in_addr remote_ip, int remote_port,
  int cseq) {
  (void)cfg;
  if (!local_port) return -1;
  if (call_id_number && strlen(call_id_number) >= CALLID_NUM_SIZE) return -1;
  if (call_id_host && strlen(call_id_host) >= CALLID_HOST_SIZE) return -1;

  neco_mutex_lock(&rtp_mutex);

  /* Already active? (e.g. duplicate INVITE) */
  for (int i = 0; i < RTP_RELAY_TABLE_SIZE; i++) {
    if (rtp_table[i].rtp_rx_sock <= 0) continue;
    if (compare_callid(call_id_number, call_id_host, rtp_table[i].callid_number, rtp_table[i].callid_host) != 0)
      continue;
    if (rtp_table[i].direction != rtp_direction || rtp_table[i].media_stream_no != media_stream_no)
      continue;
    rtp_table[i].remote_port = remote_port;
    rtp_table[i].remote_ipaddr = remote_ip;
    if (cseq > rtp_table[i].cseq) rtp_table[i].cseq = cseq;
    *local_port = rtp_table[i].local_port;
    neco_mutex_unlock(&rtp_mutex);
    return 0;
  }

  int freeidx = -1;
  for (int j = 0; j < RTP_RELAY_TABLE_SIZE; j++) {
    if (rtp_table[j].rtp_rx_sock == 0) { freeidx = j; break; }
  }
  if (freeidx < 0) {
    neco_mutex_unlock(&rtp_mutex);
    return -1;
  }

  int num_ports = rtp_port_high - rtp_port_low + 1;
  if (num_ports <= 0) num_ports = 1;
  int port = 0, sock = -1, sock_con = -1;
  if (rtp_prev_port < rtp_port_low || rtp_prev_port > rtp_port_high)
    rtp_prev_port = rtp_port_high;
  for (int k = 0; k < num_ports; k++) {
    int p = (rtp_prev_port - rtp_port_low + 1 + k) % num_ports + rtp_port_low;
    if ((p & 1) != 0) continue;
    int in_use = 0;
    for (int j = 0; j < RTP_RELAY_TABLE_SIZE; j++) {
      if (rtp_table[j].rtp_rx_sock == 0) continue;
      if (rtp_table[j].local_ipaddr.s_addr != local_ip.s_addr) continue;
      if (rtp_table[j].local_port == p || rtp_table[j].local_port == p + 1 ||
          rtp_table[j].local_port + 1 == p || rtp_table[j].local_port + 1 == p + 1)
        in_use = 1;
    }
    if (in_use) continue;
    sock = sockbind(local_ip, p);
    if (sock < 0) continue;
    sock_con = sockbind(local_ip, p + 1);
    if (sock_con < 0) {
      close(sock);
      continue;
    }
    port = p;
    rtp_prev_port = p + 1;
    break;
  }

  if (port == 0 || sock < 0 || sock_con < 0) {
    neco_mutex_unlock(&rtp_mutex);
    return -1;
  }

  rtp_table[freeidx].rtp_rx_sock = sock;
  rtp_table[freeidx].rtp_con_rx_sock = sock_con;
  rtp_table[freeidx].rtp_tx_sock = 0;
  rtp_table[freeidx].rtp_con_tx_sock = 0;
  snprintf(rtp_table[freeidx].callid_number, CALLID_NUM_SIZE, "%s", call_id_number ? call_id_number : "");
  snprintf(rtp_table[freeidx].callid_host, CALLID_HOST_SIZE, "%s", call_id_host ? call_id_host : "");
  rtp_table[freeidx].direction = rtp_direction;
  rtp_table[freeidx].call_direction = call_direction;
  rtp_table[freeidx].media_stream_no = media_stream_no;
  rtp_table[freeidx].cseq = cseq;
  rtp_table[freeidx].local_ipaddr = local_ip;
  rtp_table[freeidx].local_port = port;
  rtp_table[freeidx].remote_ipaddr = remote_ip;
  rtp_table[freeidx].remote_port = remote_port;
  rtp_table[freeidx].timestamp = time(NULL);
  rtp_table[freeidx].opposite_entry = -1;

  match_socket(freeidx);
  rtp_recreate_fdset();
  *local_port = port;
  neco_mutex_unlock(&rtp_mutex);
  return 0;
}

int rtp_relay_stop_fwd(const char *call_id_number, const char *call_id_host,
  int rtp_direction, int media_stream_no, int cseq) {
  neco_mutex_lock(&rtp_mutex);
  int found = 0;
  for (int i = 0; i < RTP_RELAY_TABLE_SIZE; i++) {
    if (rtp_table[i].rtp_rx_sock <= 0) continue;
    if (compare_callid(call_id_number, call_id_host, rtp_table[i].callid_number, rtp_table[i].callid_host) != 0)
      continue;
    if (rtp_table[i].direction != rtp_direction) continue;
    if (media_stream_no >= 0 && rtp_table[i].media_stream_no != media_stream_no) continue;
    if (cseq >= 0 && rtp_table[i].cseq > cseq) continue;

    if (rtp_table[i].rtp_rx_sock > 0) close(rtp_table[i].rtp_rx_sock);
    if (rtp_table[i].rtp_con_rx_sock > 0) close(rtp_table[i].rtp_con_rx_sock);
    if (rtp_table[i].opposite_entry >= 0)
      rtp_table[rtp_table[i].opposite_entry].opposite_entry = -1;
    memset(&rtp_table[i], 0, sizeof(rtp_table[i]));
    found = 1;
  }
  if (found) rtp_recreate_fdset();
  neco_mutex_unlock(&rtp_mutex);
  return found ? 0 : -1;
}
