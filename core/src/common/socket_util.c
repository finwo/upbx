#include "common/socket_util.h"
#include "rxi/log.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/stat.h>

int set_socket_nonblocking(int fd, int nonblock) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  if (nonblock)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0 ? 0 : -1;
}

int *tcp_listen(const char *addr, const char *default_host, const char *default_port) {
  char host[256] = "";
  char port[32] = "";

  if (default_host && default_host[0]) {
    snprintf(host, sizeof(host), "%s", default_host);
  }
  if (default_port && default_port[0]) {
    snprintf(port, sizeof(port), "%s", default_port);
  }

  if (!addr || !addr[0]) {
    if (!host[0] || !port[0]) {
      log_error("tcp_listen: empty address and no defaults");
      return NULL;
    }
  } else if (addr[0] == '[') {
    const char *close_bracket = strchr(addr, ']');
    if (!close_bracket) {
      log_error("tcp_listen: invalid IPv6 format: missing ']'");
      return NULL;
    }
    size_t hlen = (size_t)(close_bracket - addr - 1);
    if (hlen > 0) {
      if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
      memcpy(host, addr + 1, hlen);
      host[hlen] = '\0';
    }
    const char *colon = close_bracket + 1;
    if (*colon == ':') {
      snprintf(port, sizeof(port), "%s", colon + 1);
    } else if (*colon != '\0') {
      log_error("tcp_listen: invalid IPv6 format: expected ':' after ']'");
      return NULL;
    }
  } else {
    int leading_colon = (addr[0] == ':');
    const char *p = leading_colon ? addr + 1 : addr;
    int is_port_only = 1;
    for (const char *q = p; *q; q++) {
      if (*q < '0' || *q > '9') { is_port_only = 0; break; }
    }

    const char *colon = strrchr(addr, ':');
    if (leading_colon && is_port_only) {
      snprintf(port, sizeof(port), "%s", p);
    } else if (is_port_only) {
      if (default_host && default_host[0]) {
        snprintf(host, sizeof(host), "%s", default_host);
      }
      snprintf(port, sizeof(port), "%s", p);
    } else if (colon) {
      size_t hlen = (size_t)(colon - addr);
      if (hlen > 0) {
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, addr, hlen);
        host[hlen] = '\0';
      }
      snprintf(port, sizeof(port), "%s", colon + 1);
    } else {
      snprintf(host, sizeof(host), "%s", addr);
    }
  }

  if (!port[0]) {
    log_error("tcp_listen: no port specified");
    return NULL;
  }

  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(host[0] ? host : NULL, port, &hints, &res) != 0 || !res) {
    log_error("tcp_listen: getaddrinfo failed for %s:%s", host, port);
    return NULL;
  }

  int *fds = malloc(sizeof(int) * 3);
  if (!fds) {
    freeaddrinfo(res);
    return NULL;
  }
  fds[0] = 0;

  int listen_all = (host[0] == '\0');
  struct addrinfo *p;

  for (p = res; p; p = p->ai_next) {
    if (p->ai_family == AF_INET) {
      int fd = socket(AF_INET, SOCK_STREAM, 0);
      if (fd < 0) continue;
      int opt = 1;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 && listen(fd, 8) == 0) {
        set_socket_nonblocking(fd, 1);
        fds[++fds[0]] = fd;
      } else {
        close(fd);
      }
    } else if (p->ai_family == AF_INET6 && listen_all) {
      int fd = socket(AF_INET6, SOCK_STREAM, 0);
      if (fd < 0) continue;
      int opt = 1;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
      if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 && listen(fd, 8) == 0) {
        set_socket_nonblocking(fd, 1);
        fds[++fds[0]] = fd;
      } else {
        close(fd);
      }
    }
  }

  freeaddrinfo(res);

  if (fds[0] == 0) {
    log_error("tcp_listen: failed to bind to %s:%s", host, port);
    free(fds);
    return NULL;
  }

  return fds;
}

int *udp_recv(const char *addr, const char *default_host, const char *default_port) {
  char host[256] = "";
  char port[32] = "";

  if (default_host && default_host[0]) {
    snprintf(host, sizeof(host), "%s", default_host);
  }
  if (default_port && default_port[0]) {
    snprintf(port, sizeof(port), "%s", default_port);
  }

  if (!addr || !addr[0]) {
    if (!host[0] || !port[0]) {
      log_error("udp_recv: empty address and no defaults");
      return NULL;
    }
  } else if (addr[0] == '[') {
    const char *close_bracket = strchr(addr, ']');
    if (!close_bracket) {
      log_error("udp_recv: invalid IPv6 format: missing ']'");
      return NULL;
    }
    size_t hlen = (size_t)(close_bracket - addr - 1);
    if (hlen > 0) {
      if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
      memcpy(host, addr + 1, hlen);
      host[hlen] = '\0';
    }
    const char *colon = close_bracket + 1;
    if (*colon == ':') {
      snprintf(port, sizeof(port), "%s", colon + 1);
    } else if (*colon != '\0') {
      log_error("udp_recv: invalid IPv6 format: expected ':' after ']'");
      return NULL;
    }
  } else {
    int leading_colon = (addr[0] == ':');
    const char *p = leading_colon ? addr + 1 : addr;
    int is_port_only = 1;
    for (const char *q = p; *q; q++) {
      if (*q < '0' || *q > '9') { is_port_only = 0; break; }
    }

    const char *colon = strrchr(addr, ':');
    if (leading_colon && is_port_only) {
      snprintf(port, sizeof(port), "%s", p);
    } else if (is_port_only) {
      if (default_host && default_host[0]) {
        snprintf(host, sizeof(host), "%s", default_host);
      }
      snprintf(port, sizeof(port), "%s", p);
    } else if (colon) {
      size_t hlen = (size_t)(colon - addr);
      if (hlen > 0) {
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, addr, hlen);
        host[hlen] = '\0';
      }
      snprintf(port, sizeof(port), "%s", colon + 1);
    } else {
      snprintf(host, sizeof(host), "%s", addr);
    }
  }

  if (!port[0]) {
    log_error("udp_recv: no port specified");
    return NULL;
  }

  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(host[0] ? host : NULL, port, &hints, &res) != 0 || !res) {
    log_error("udp_recv: getaddrinfo failed for %s:%s", host, port);
    return NULL;
  }

  int *fds = malloc(sizeof(int) * 3);
  if (!fds) {
    freeaddrinfo(res);
    return NULL;
  }
  fds[0] = 0;

  int listen_all = (host[0] == '\0');
  struct addrinfo *p;

  for (p = res; p; p = p->ai_next) {
    if (p->ai_family == AF_INET) {
      int fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (fd < 0) continue;
      int opt = 1;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      if (bind(fd, p->ai_addr, p->ai_addrlen) == 0) {
        set_socket_nonblocking(fd, 1);
        fds[++fds[0]] = fd;
      } else {
        close(fd);
      }
    } else if (p->ai_family == AF_INET6 && listen_all) {
      int fd = socket(AF_INET6, SOCK_DGRAM, 0);
      if (fd < 0) continue;
      int opt = 1;
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
      if (bind(fd, p->ai_addr, p->ai_addrlen) == 0) {
        set_socket_nonblocking(fd, 1);
        fds[++fds[0]] = fd;
      } else {
        close(fd);
      }
    }
  }

  freeaddrinfo(res);

  if (fds[0] == 0) {
    log_error("udp_recv: failed to bind to %s:%s", host, port);
    free(fds);
    return NULL;
  }

  return fds;
}

int *unix_listen(const char *path, int sock_type) {
  if (!path || !path[0]) {
    log_error("unix_listen: empty path");
    return NULL;
  }

  char *path_copy = strdup(path);
  if (!path_copy) {
    return NULL;
  }

  char *dir = strdup(path);
  if (!dir) {
    free(path_copy);
    return NULL;
  }

  char *last_slash = strrchr(dir, '/');
  if (last_slash && last_slash != dir) {
    *last_slash = '\0';
    if (strlen(dir) > 0) {
      mkdir(dir, 0755);
    }
  } else if (!last_slash) {
    dir[0] = '.';
    dir[1] = '\0';
  }
  free(dir);

  unlink(path_copy);

  int *fds = malloc(sizeof(int) * 2);
  if (!fds) {
    free(path_copy);
    return NULL;
  }
  fds[0] = 0;

  int fd = socket(AF_UNIX, sock_type, 0);
  if (fd < 0) {
    log_error("unix_listen: socket failed: %s", strerror(errno));
    free(path_copy);
    free(fds);
    return NULL;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path_copy, sizeof(addr.sun_path) - 1);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    log_error("unix_listen: bind failed: %s", strerror(errno));
    close(fd);
    free(path_copy);
    free(fds);
    return NULL;
  }

  if (sock_type == SOCK_DGRAM) {
    chmod(path_copy, 0777);
  } else if (sock_type == SOCK_STREAM) {
    if (listen(fd, 8) < 0) {
      log_error("unix_listen: listen failed: %s", strerror(errno));
      close(fd);
      unlink(path_copy);
      free(path_copy);
      free(fds);
      return NULL;
    }
  }

  set_socket_nonblocking(fd, 1);

  fds[++fds[0]] = fd;

  free(path_copy);
  return fds;
}
