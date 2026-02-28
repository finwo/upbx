#ifndef UPBX_SOCKET_UTIL_H
#define UPBX_SOCKET_UTIL_H

/* Set socket blocking (0) or non-blocking (1). Returns 0 on success, -1 on error. */
int set_socket_nonblocking(int fd, int nonblock);

/* Create listening sockets. Supports dual-stack when host is empty.
 * addr can be "port", "host:port", or "[ipv6]:port". Missing host uses default_host,
 * missing port uses default_port.
 * Returns int array: index 0 = count, index 1+ = socket fds. Caller must free.
 * On error returns NULL. */
int *tcp_listen(const char *addr, const char *default_host, const char *default_port);

/* Create UDP receiving sockets. Same semantics as tcp_listen(). */
int *udp_recv(const char *addr, const char *default_host, const char *default_port);

/* Create Unix domain socket. path is the socket path, sock_type is SOCK_DGRAM or SOCK_STREAM.
 * Returns int array: index 0 = count, index 1 = socket fd. Caller must free.
 * On error returns NULL. */
int *unix_listen(const char *path, int sock_type);

#endif
