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
#include "AppModule/sip_parse.h"
#include "common/hexdump.h"

static int udp_send_response(int fd, const struct sockaddr *dst, const char *msg, size_t len) {
  socklen_t dst_len = (dst->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  ssize_t sent = sendto(fd, msg, len, 0, dst, dst_len);
  if (sent < 0) {
    log_error("sip_udp: sendto failed: %s", strerror(errno));
    return -1;
  }
  log_trace("sip_udp: sent %zd bytes response", sent);
  return 0;
}

#define UDP_BUF_SIZE 8192

static int udp_sockfd = -1;

PT_THREAD(sip_udp_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
  static char buf[UDP_BUF_SIZE];
  static struct sockaddr_storage src_addr;
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

    char src_ip[INET6_ADDRSTRLEN];
    int src_port = 0;
    if (src_addr.ss_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)&src_addr;
      inet_ntop(AF_INET, &sin->sin_addr, src_ip, sizeof(src_ip));
      src_port = ntohs(sin->sin_port);
    } else if (src_addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
      inet_ntop(AF_INET6, &sin6->sin6_addr, src_ip, sizeof(src_ip));
      src_port = ntohs(sin6->sin6_port);
    }
    log_trace("sip_udp: received %zd bytes from %s:%d", n, src_ip, src_port);

    if (sip_security_check_raw(buf, (size_t)n) != 0) {
      log_warn("sip_udp: security check failed from %s:%d", src_ip, src_port);
      log_hexdump_trace(buf, (size_t)n);
      continue;
    }

    log_trace("sip_udp: message passed security check, processing...");
    
    size_t resp_len;
    char *resp = sip_process_request(buf, (size_t)n, &resp_len, &src_addr, -1);
    if (resp) {
      udp_send_response(udp_sockfd, (struct sockaddr *)&src_addr, resp, resp_len);
      free(resp);
    }
    
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
