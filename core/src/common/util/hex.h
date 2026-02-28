#ifndef UPBX_COMMON_UTIL_HEX_H
#define UPBX_COMMON_UTIL_HEX_H

#include <stddef.h>

void hex_bytes_to_str(const unsigned char *bytes, size_t len, char *out);

int hex_char_to_val(char c);

int hex_str_to_bytes(const char *hex, size_t hex_len, unsigned char *out, size_t out_size);

#endif
