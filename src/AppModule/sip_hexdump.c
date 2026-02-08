/*
 * Canonical hexdump at trace level; shared by sip_server and trunk_reg.
 */
#include <stddef.h>
#include <stdio.h>

#include "rxi/log.h"

void log_hexdump_trace(const char *buf, size_t len) {
  log_trace("%s", __func__);
  char line[96];
  const size_t row = 16;
  for (size_t off = 0; off < len; off += row) {
    size_t n = row;
    if (off + n > len)
      n = len - off;
    size_t o = 0;
    o += (size_t)snprintf(line + o, sizeof(line) - o, "%08zx  ", off);
    for (size_t i = 0; i < row; i++) {
      if (i < n)
        o += (size_t)snprintf(line + o, sizeof(line) - o, "%02x ", (unsigned char)buf[off + i]);
      else
        o += (size_t)snprintf(line + o, sizeof(line) - o, "   ");
      if (i == 7)
        o += (size_t)snprintf(line + o, sizeof(line) - o, " ");
    }
    o += (size_t)snprintf(line + o, sizeof(line) - o, " |");
    for (size_t i = 0; i < n; i++) {
      unsigned char c = (unsigned char)buf[off + i];
      line[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    o += (size_t)snprintf(line + o, sizeof(line) - o, "|");
    log_trace("%s", line);
  }
}
