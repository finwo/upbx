#ifndef UPBX_HEX_H
#define UPBX_HEX_H

#include <stddef.h>

int hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size);
int hex_decode(const char *in, uint8_t *out, size_t out_size);

#endif
