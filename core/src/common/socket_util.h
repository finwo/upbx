#ifndef UDPHOLE_SOCKET_UTIL_H
#define UDPHOLE_SOCKET_UTIL_H

int set_socket_nonblocking(int fd, int nonblock);

int *tcp_listen(const char *addr, const char *default_host, const char *default_port);

int *udp_recv(const char *addr, const char *default_host, const char *default_port);

int *unix_listen(const char *path, int sock_type, const char *owner);

#endif