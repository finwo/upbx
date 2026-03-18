#include "sdp/sdp.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *sdp_get_ip_port(const char *sdp, size_t sdp_len, char *ip_out, int *port_out) {
  if (!sdp || !ip_out || !port_out) return NULL;

  *ip_out = '\0';
  *port_out = 0;

  const char *c_line = strstr(sdp, "c=IN ");
  if (!c_line) return NULL;

  c_line += 5;
  while (*c_line == ' ') c_line++;

  const char *ip_end = c_line;
  while (*ip_end && !isspace((unsigned char)*ip_end)) ip_end++;

  if (ip_end == c_line) return NULL;

  size_t ip_len = ip_end - c_line;
  if (ip_len > 63) ip_len = 63;
  memcpy(ip_out, c_line, ip_len);
  ip_out[ip_len] = '\0';

  const char *m_line = strstr(sdp, "m=audio ");
  if (!m_line) return NULL;

  m_line += 8;
  while (*m_line == ' ') m_line++;

  const char *port_end = m_line;
  while (*port_end && isdigit((unsigned char)*port_end)) port_end++;

  char port_buf[16] = {0};
  size_t port_len = port_end - m_line;
  if (port_len > 15) port_len = 15;
  memcpy(port_buf, m_line, port_len);
  *port_out = atoi(port_buf);

  return (char *)ip_out;
}

char *sdp_replace_ip_port(const char *sdp, size_t sdp_len, const char *ip, int port, size_t *out_len) {
  if (!sdp || !ip || !out_len) return NULL;

  char *result = malloc(sdp_len + 128);
  if (!result) return NULL;

  size_t result_len = 0;
  const char *pos = sdp;

  while (pos < sdp + sdp_len) {
    if (strncmp(pos, "c=IN ", 5) == 0) {
      memcpy(result + result_len, "c=IN IP4 ", 9);
      result_len += 9;
      size_t ip_len = strlen(ip);
      memcpy(result + result_len, ip, ip_len);
      result_len += ip_len;
      result[result_len++] = '\r';
      result[result_len++] = '\n';

      pos = strchr(pos, '\n');
      if (!pos) break;
      pos++;
      continue;
    }

    if (strncmp(pos, "m=audio ", 8) == 0) {
      memcpy(result + result_len, "m=audio ", 8);
      result_len += 8;

      char port_str[16];
      snprintf(port_str, sizeof(port_str), "%d", port);
      size_t port_len = strlen(port_str);
      memcpy(result + result_len, port_str, port_len);
      result_len += port_len;

      pos = strchr(pos, ' ');
      if (!pos) break;
      pos++;

      while (pos < sdp + sdp_len && *pos != '\n') {
        result[result_len++] = *pos++;
      }
      continue;
    }

    result[result_len++] = *pos++;
  }

  *out_len = result_len;
  return result;
}
