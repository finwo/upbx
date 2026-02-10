#include "common/socket_util.h"
#include <fcntl.h>
#include <unistd.h>

int set_socket_nonblocking(int fd, int nonblock) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  if (nonblock)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0 ? 0 : -1;
}
