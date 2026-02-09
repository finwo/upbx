#ifndef UPBX_SOCKET_UTIL_H
#define UPBX_SOCKET_UTIL_H

/* Set socket blocking (0) or non-blocking (1). Returns 0 on success, -1 on error. */
int set_socket_nonblocking(int fd, int nonblock);

#endif
