#include <stdint.h>
#include <ctype.h>
#include "util/hex.h"

int hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size) {
    if (out_size < in_len * 2 + 1) return -1;
    for (size_t i = 0; i < in_len; i++) {
        static const char hex[] = "0123456789abcdef";
        out[i * 2] = hex[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[in[i] & 0xf];
    }
    out[in_len * 2] = '\0';
    return in_len * 2;
}

int hex_decode(const char *in, uint8_t *out, size_t out_size) {
    size_t len = 0;
    while (in[0] && in[1]) {
        if (len >= out_size) return -1;
        int hi = tolower((unsigned char)in[0]);
        int lo = tolower((unsigned char)in[1]);
        if (!isxdigit(hi) || !isxdigit(lo)) return -1;
        uint8_t byte = 0;
        if (hi >= 'a') byte |= (hi - 'a' + 10) << 4;
        else byte |= (hi - '0') << 4;
        if (lo >= 'a') byte |= lo - 'a' + 10;
        else byte |= lo - '0';
        out[len++] = byte;
        in += 2;
    }
    return (int)len;
}
