#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rxi/log.h"
#include "config.h"
#include "AppModule/rtp/client.h"

static int send_command(const char *cmd, char *response, size_t resp_size) {
  char *socket_path = config_get_rtp_socket();
  if (!socket_path) {
    socket_path = strdup("/var/run/rtpproxy.sock");
  }

  if (strncmp(socket_path, "unix://", 7) == 0) {
    char *p = strdup(socket_path + 7);
    free(socket_path);
    socket_path = p;
  }

  int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0) {
    free(socket_path);
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  free(socket_path);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(fd);
    return -1;
  }

  size_t cmd_len = strlen(cmd);
  if (send(fd, cmd, cmd_len, 0) != (ssize_t)cmd_len) {
    close(fd);
    return -1;
  }

  ssize_t n = recv(fd, response, resp_size - 1, 0);
  close(fd);

  if (n <= 0) return -1;
  response[n] = '\0';
  return 0;
}

static int parse_response(const char *response, rtp_session_info_t *info) {
  info->port = 0;
  free(info->advertise_ip);
  info->advertise_ip = NULL;

  if (response[0] == 'E') {
    int errcode = atoi(response + 1);
    log_error("rtpproxy error: %d", errcode);
    return -1;
  }

  if (response[0] >= '0' && response[0] <= '9') {
    const char *p = response;
    char *end;
    info->port = (int)strtol(p, &end, 10);
    
    if (end && *end == ' ') {
      p = end + 1;
      while (*p && (*p == ' ' || *p == '\r' || *p == '\n')) p++;
      if (*p) {
        info->advertise_ip = strdup(p);
        char *nl = strchr(info->advertise_ip, '\r');
        if (nl) *nl = '\0';
        nl = strchr(info->advertise_ip, '\n');
        if (nl) *nl = '\0';
      }
    }
    return 0;
  }

  return -1;
}

int rtp_client_create_session(const char *call_id, const char *remote_ip, int remote_port, const char *from_tag, rtp_session_info_t *info) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "A %s %s %d %s\n", call_id, remote_ip, remote_port, from_tag);

  char response[256];
  if (send_command(cmd, response, sizeof(response)) != 0) {
    log_error("rtp_client: failed to send create command");
    return -1;
  }

  return parse_response(response, info);
}

int rtp_client_lookup_session(const char *call_id, const char *remote_ip, int remote_port, const char *from_tag, rtp_session_info_t *info) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "L %s %s %d %s\n", call_id, remote_ip, remote_port, from_tag);

  char response[256];
  if (send_command(cmd, response, sizeof(response)) != 0) {
    log_error("rtp_client: failed to send lookup command");
    return -1;
  }

  return parse_response(response, info);
}

int rtp_client_delete_session(const char *call_id, const char *from_tag, const char *to_tag) {
  char cmd[512];
  if (to_tag && to_tag[0]) {
    snprintf(cmd, sizeof(cmd), "D %s %s %s\n", call_id, from_tag, to_tag);
  } else {
    snprintf(cmd, sizeof(cmd), "D %s %s\n", call_id, from_tag);
  }

  char response[256];
  if (send_command(cmd, response, sizeof(response)) != 0) {
    log_error("rtp_client: failed to send delete command");
    return -1;
  }

  if (response[0] == '0') return 0;
  return -1;
}

void rtp_client_free_info(rtp_session_info_t *info) {
  if (info) {
    free(info->advertise_ip);
    info->advertise_ip = NULL;
    info->port = 0;
  }
}