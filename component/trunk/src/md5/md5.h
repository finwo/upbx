#ifndef TRK_MD5_H
#define TRK_MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t  buffer[64];
} trk_md5_ctx;

void trk_md5_init(trk_md5_ctx *ctx);
void trk_md5_update(trk_md5_ctx *ctx, const uint8_t *data, size_t len);
void trk_md5_final(trk_md5_ctx *ctx, uint8_t digest[16]);
void trk_md5(const uint8_t *data, size_t len, uint8_t digest[16]);
void trk_md5_hex(const uint8_t digest[16], char hex_out[33]);

#endif
