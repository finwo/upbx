#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "common/pt.h"
#include "common/socket_util.h"
#include "config.h"
#include "AppModule/scheduler/daemon.h"
#include "AppModule/sip/transport_udp.h"

#define UDP_BUF_SIZE 8192

static int udp_sockfd = -1;

PT_THREAD(sip_udp_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  static char buf[UDP_BUF_SIZE];
  static struct sockaddr_in src_addr;
  static socklen_t src_len;

  PT_BEGIN(pt);

  char *listen_addr = config_get_listen();
  if (!listen_addr) {
    listen_addr = strdup("0.0.0.0:5060");
  }

  char host[256] = "0.0.0.0";
  int port = 5060;
  const char *colon = strrchr(listen_addr, ':');
  if (colon) {
    size_t hlen = (size_t)(colon - listen_addr);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, listen_addr, hlen);
    host[hlen] = '\0';
    port = atoi(colon + 1);
  }
  free(listen_addr);

  udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_sockfd < 0) {
    log_error("sip_udp: socket failed: %s", strerror(errno));
    PT_EXIT(pt);
  }

  int opt = 1;
  setsockopt(udp_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(host);
  addr.sin_port = htons(port);

  if (bind(udp_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    log_error("sip_udp: bind failed: %s", strerror(errno));
    close(udp_sockfd);
    udp_sockfd = -1;
    PT_EXIT(pt);
  }

  set_socket_nonblocking(udp_sockfd, 1);

  task->read_fds = &udp_sockfd;
  task->read_fds_count = 1;

  log_info("sip_udp: listening on %s:%d", host, port);

  for (;;) {
    int ready_fd = -1;
    PT_WAIT_UNTIL(pt, pt_task_has_data(task, &ready_fd) == 0 && ready_fd == udp_sockfd);

    src_len = sizeof(src_addr);
    ssize_t n = recvfrom(udp_sockfd, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr *)&src_addr, &src_len);

    if (n <= 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        log_error("sip_udp: recvfrom failed: %s", strerror(errno));
      }
      continue;
    }

    buf[n] = '\0';

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));
    log_trace("sip_udp: received %zd bytes from %s:%d", n, src_ip, ntohs(src_addr.sin_port));

    (void)timestamp;
  }

  PT_END(pt);
}

void sip_udp_start(void) {
  appmodule_pt_add(sip_udp_pt, NULL);
}

void sip_udp_stop(void) {
  if (udp_sockfd >= 0) {
    close(udp_sockfd);
    udp_sockfd = -1;
  }
}