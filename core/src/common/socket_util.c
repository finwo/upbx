#include "common/socket_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "rxi/log.h"

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
  char port[32]  = "";

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
    int         leading_colon = (addr[0] == ':');
    const char *p             = leading_colon ? addr + 1 : addr;
    int         is_port_only  = 1;
    for (const char *q = p; *q; q++) {
      if (*q < '0' || *q > '9') {
        is_port_only = 0;
        break;
      }
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
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = AI_PASSIVE;
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

  int              listen_all = (host[0] == '\0');
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
  char port[32]  = "";

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
    int         leading_colon = (addr[0] == ':');
    const char *p             = leading_colon ? addr + 1 : addr;
    int         is_port_only  = 1;
    for (const char *q = p; *q; q++) {
      if (*q < '0' || *q > '9') {
        is_port_only = 0;
        break;
      }
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
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags    = AI_PASSIVE;
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

  int              listen_all = (host[0] == '\0');
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

int *unix_listen(const char *path, int sock_type, const char *owner) {
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

  if (owner && owner[0]) {
    uid_t uid        = -1;
    gid_t gid        = -1;
    char *owner_copy = strdup(owner);
    if (owner_copy) {
      char *colon = strchr(owner_copy, ':');
      if (colon) {
        *colon = '\0';
        colon++;
        if (colon[0]) {
          struct passwd *pw = getpwnam(owner_copy);
          if (pw) {
            uid              = pw->pw_uid;
            struct group *gr = getgrnam(colon);
            if (gr) {
              gid = gr->gr_gid;
            }
          }
        }
      } else {
        struct passwd *pw = getpwnam(owner_copy);
        if (pw) {
          uid = pw->pw_uid;
          gid = pw->pw_gid;
        }
      }
      free(owner_copy);
    }
    if (uid != (uid_t)-1 || gid != (gid_t)-1) {
      if (fchown(fd, uid, gid) < 0) {
        log_error("unix_listen: fchown failed: %s", strerror(errno));
        close(fd);
        unlink(path_copy);
        free(path_copy);
        free(fds);
        return NULL;
      }
    }
  }

  if (sock_type == SOCK_STREAM) {
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

int *merge_fd_arrays(int **arrays, int count) {
  if (!arrays || count <= 0) {
    return NULL;
  }

  int total_count = 0;
  for (int i = 0; i < count; i++) {
    if (arrays[i] && arrays[i][0] > 0) {
      total_count += arrays[i][0];
    }
  }

  if (total_count == 0) {
    for (int i = 0; i < count; i++) {
      free(arrays[i]);
    }
    return NULL;
  }

  int *merged = malloc(sizeof(int) * (total_count + 1));
  if (!merged) {
    for (int i = 0; i < count; i++) {
      free(arrays[i]);
    }
    return NULL;
  }

  merged[0] = 0;
  int idx = 1;

  for (int i = 0; i < count; i++) {
    if (arrays[i] && arrays[i][0] > 0) {
      for (int j = 1; j <= arrays[i][0]; j++) {
        merged[idx++] = arrays[i][j];
      }
      merged[0] += arrays[i][0];
    }
    free(arrays[i]);
  }

  return merged;
}

void sockaddr_to_string(const struct sockaddr *addr, char *buf, size_t buf_size) {
  if (!addr || !buf || buf_size == 0) return;

  if (addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    inet_ntop(AF_INET, &sin->sin_addr, buf, buf_size);
    size_t len = strlen(buf);
    if (buf_size - len > 6) {
      snprintf(buf + len, buf_size - len, ":%d", ntohs(sin->sin_port));
    }
  } else if (addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    buf[0]                    = '[';
    inet_ntop(AF_INET6, &sin6->sin6_addr, buf + 1, (socklen_t)(buf_size - 1));
    size_t len = strlen(buf);
    if (buf_size - len > 6) {
      snprintf(buf + len, buf_size - len, "]:%d", ntohs(sin6->sin6_port));
    }
  } else {
    buf[0] = '\0';
  }
}

int string_to_sockaddr(const char *str, struct sockaddr_storage *addr) {
  if (!str || !addr) return -1;
  memset(addr, 0, sizeof(*addr));

  const char *port_str = strrchr(str, ':');
  if (!port_str) return -1;

  char   host[256];
  size_t host_len = (size_t)(port_str - str);
  if (host_len >= sizeof(host)) return -1;
  memcpy(host, str, host_len);
  host[host_len] = '\0';

  int port = atoi(port_str + 1);
  if (port <= 0 || port > 65535) return -1;

  if (host[0] == '[' && host[host_len - 1] == ']') {
    host[host_len - 1]        = '\0';
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    sin6->sin6_family         = AF_INET6;
    sin6->sin6_port           = htons((uint16_t)port);
    if (inet_pton(AF_INET6, host + 1, &sin6->sin6_addr) != 1) return -1;
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    sin->sin_family         = AF_INET;
    sin->sin_port           = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sin->sin_addr) != 1) return -1;
  }

  return 0;
}

int sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b) {
  if (!a || !b || a->sa_family != b->sa_family) return 0;

  if (a->sa_family == AF_INET) {
    struct sockaddr_in *sin_a = (struct sockaddr_in *)a;
    struct sockaddr_in *sin_b = (struct sockaddr_in *)b;
    return sin_a->sin_addr.s_addr == sin_b->sin_addr.s_addr && sin_a->sin_port == sin_b->sin_port;
  } else if (a->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6_a = (struct sockaddr_in6 *)a;
    struct sockaddr_in6 *sin6_b = (struct sockaddr_in6 *)b;
    return memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr, sizeof(sin6_a->sin6_addr)) == 0 && sin6_a->sin6_port == sin6_b->sin6_port;
  }
  return 0;
}
