#include "common/util/hex.h"

void hex_bytes_to_str(const unsigned char *bytes, size_t len, char *out) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2]     = hex[(bytes[i] >> 4) & 0x0f];
    out[i * 2 + 1] = hex[bytes[i] & 0x0f];
  }
  out[len * 2] = '\0';
}

int hex_char_to_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

int hex_str_to_bytes(const char *hex, size_t hex_len, unsigned char *out, size_t out_size) {
  if (hex_len % 2 != 0) return -1;
  size_t bytes = hex_len / 2;
  if (bytes > out_size) return -1;

  for (size_t i = 0; i < bytes; i++) {
    int hi = hex_char_to_val(hex[i * 2]);
    int lo = hex_char_to_val(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}
