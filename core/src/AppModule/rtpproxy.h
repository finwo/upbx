/*
 * RTP Proxy: handles both UDP and TCP RTP forwarding.
 *
 * All media passes through the PBX RTP proxy; no direct peer-to-peer RTP.
 * Supports:
 *   - UDP to UDP (existing behavior)
 *   - TCP to UDP (phone uses TCP, PBX forwards to UDP)
 *   - UDP to TCP (phone receives TCP)
 *   - TCP to TCP (both use TCP)
 */
#ifndef UPBX_RTPPROXY_H
#define UPBX_RTPPROXY_H

#include <stddef.h>
#include <sys/select.h>
#include <netinet/in.h>

#define RTP_BUF_SIZE 1520

void rtpproxy_init(void);
void rtpproxy_cleanup(void);

int rtpproxy_alloc_udp_port(struct in_addr local_ip, int port_low, int port_high,
                             int *sock, int *port);

int rtpproxy_alloc_tcp_port(struct in_addr local_ip, int port_low, int port_high,
                           int *sock, int *port);

int rtpproxy_connect_tcp(const char *remote_ip, int remote_port);

void rtpproxy_register_call(int forward_sock, int tcp_listen_sock, int tcp_conn_sock,
                            struct sockaddr_in *remote, const char *transport);

void rtpproxy_unregister_call(int forward_sock, int tcp_listen_sock, int tcp_conn_sock);

void rtpproxy_fill_fds(fd_set *read_set, int *maxfd);

void rtpproxy_process(fd_set *read_set,
                      int forward_sock_a, int tcp_listen_a, int tcp_conn_a, struct sockaddr_in *remote_a,
                      int forward_sock_b, int tcp_listen_b, int tcp_conn_b, struct sockaddr_in *remote_b,
                      time_t *active_at, unsigned long *pkts_a2b, unsigned long *pkts_b2a);

#endif
