/*
 * MD5 (RFC 1321) -- reference implementation in C.
 * Public domain. No external dependencies.
 */
#include "common/md5.h"
#include <string.h>
#include <stdint.h>

#define F(x, y, z) U32(((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) U32(((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) U32((x) ^ (y) ^ (z))
#define I(x, y, z) U32((y) ^ ((x) | (~(z))))

#define U32(x) ((x) & 0xffffffffu)
#define ROTL32(v, n) (U32(((v) << (n)) | ((v) >> (32 - (n)))))

#define STEP(f, a, b, c, d, x, t, s) do { \
  (a) = U32((a) + f((b), (c), (d)) + (x) + (t)); \
  (a) = ROTL32((a), (s)); \
  (a) = U32((a) + (b)); \
} while (0)

static const unsigned int T[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static void md5_transform(unsigned int state[4], const unsigned char block[64]) {
  uint32_t a = (uint32_t)state[0], b = (uint32_t)state[1], c = (uint32_t)state[2], d = (uint32_t)state[3];
  uint32_t X[16];
  int i;

  for (i = 0; i < 16; i++)
    X[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
           ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);

  /* Round 1 */
  STEP(F, a, b, c, d, X[ 0], T[ 0],  7); STEP(F, d, a, b, c, X[ 1], T[ 1], 12);
  STEP(F, c, d, a, b, X[ 2], T[ 2], 17); STEP(F, b, c, d, a, X[ 3], T[ 3], 22);
  STEP(F, a, b, c, d, X[ 4], T[ 4],  7); STEP(F, d, a, b, c, X[ 5], T[ 5], 12);
  STEP(F, c, d, a, b, X[ 6], T[ 6], 17); STEP(F, b, c, d, a, X[ 7], T[ 7], 22);
  STEP(F, a, b, c, d, X[ 8], T[ 8],  7); STEP(F, d, a, b, c, X[ 9], T[ 9], 12);
  STEP(F, c, d, a, b, X[10], T[10], 17); STEP(F, b, c, d, a, X[11], T[11], 22);
  STEP(F, a, b, c, d, X[12], T[12],  7); STEP(F, d, a, b, c, X[13], T[13], 12);
  STEP(F, c, d, a, b, X[14], T[14], 17); STEP(F, b, c, d, a, X[15], T[15], 22);
  /* Round 2 */
  STEP(G, a, b, c, d, X[ 1], T[16],  5); STEP(G, d, a, b, c, X[ 6], T[17],  9);
  STEP(G, c, d, a, b, X[11], T[18], 14); STEP(G, b, c, d, a, X[ 0], T[19], 20);
  STEP(G, a, b, c, d, X[ 5], T[20],  5); STEP(G, d, a, b, c, X[10], T[21],  9);
  STEP(G, c, d, a, b, X[15], T[22], 14); STEP(G, b, c, d, a, X[ 4], T[23], 20);
  STEP(G, a, b, c, d, X[ 9], T[24],  5); STEP(G, d, a, b, c, X[14], T[25],  9);
  STEP(G, c, d, a, b, X[ 3], T[26], 14); STEP(G, b, c, d, a, X[ 8], T[27], 20);
  STEP(G, a, b, c, d, X[13], T[28],  5); STEP(G, d, a, b, c, X[ 2], T[29],  9);
  STEP(G, c, d, a, b, X[ 7], T[30], 14); STEP(G, b, c, d, a, X[12], T[31], 20);
  /* Round 3 */
  STEP(H, a, b, c, d, X[ 5], T[32],  4); STEP(H, d, a, b, c, X[ 8], T[33], 11);
  STEP(H, c, d, a, b, X[11], T[34], 16); STEP(H, b, c, d, a, X[14], T[35], 23);
  STEP(H, a, b, c, d, X[ 1], T[36],  4); STEP(H, d, a, b, c, X[ 4], T[37], 11);
  STEP(H, c, d, a, b, X[ 7], T[38], 16); STEP(H, b, c, d, a, X[10], T[39], 23);
  STEP(H, a, b, c, d, X[13], T[40],  4); STEP(H, d, a, b, c, X[ 0], T[41], 11);
  STEP(H, c, d, a, b, X[ 3], T[42], 16); STEP(H, b, c, d, a, X[ 6], T[43], 23);
  STEP(H, a, b, c, d, X[ 9], T[44],  4); STEP(H, d, a, b, c, X[12], T[45], 11);
  STEP(H, c, d, a, b, X[15], T[46], 16); STEP(H, b, c, d, a, X[ 2], T[47], 23);
  /* Round 4 */
  STEP(I, a, b, c, d, X[ 0], T[48],  6); STEP(I, d, a, b, c, X[ 7], T[49], 10);
  STEP(I, c, d, a, b, X[14], T[50], 15); STEP(I, b, c, d, a, X[ 5], T[51], 21);
  STEP(I, a, b, c, d, X[12], T[52],  6); STEP(I, d, a, b, c, X[ 3], T[53], 10);
  STEP(I, c, d, a, b, X[10], T[54], 15); STEP(I, b, c, d, a, X[ 1], T[55], 21);
  STEP(I, a, b, c, d, X[ 8], T[56],  6); STEP(I, d, a, b, c, X[15], T[57], 10);
  STEP(I, c, d, a, b, X[ 6], T[58], 15); STEP(I, b, c, d, a, X[13], T[59], 21);
  STEP(I, a, b, c, d, X[ 4], T[60],  6); STEP(I, d, a, b, c, X[11], T[61], 10);
  STEP(I, c, d, a, b, X[ 2], T[62], 15); STEP(I, b, c, d, a, X[ 9], T[63], 21);

  state[0] = (unsigned int)(state[0] + a); state[1] = (unsigned int)(state[1] + b);
  state[2] = (unsigned int)(state[2] + c); state[3] = (unsigned int)(state[3] + d);
}

void MD5_Init(MD5_CTX *ctx) {
  ctx->state[0] = 0x67452301u;
  ctx->state[1] = 0xefcdab89u;
  ctx->state[2] = 0x98badcfeu;
  ctx->state[3] = 0x10325476u;
  ctx->count[0] = ctx->count[1] = 0;
}

void MD5_Update(MD5_CTX *ctx, const void *data, size_t len) {
  const unsigned char *p = (const unsigned char *)data;
  unsigned int i, n;

  i = (unsigned int)((ctx->count[0] >> 3) & 63u);
  ctx->count[0] += (unsigned int)(len << 3);
  if (ctx->count[0] < (len << 3))
    ctx->count[1]++;
  ctx->count[1] += (unsigned int)(len >> 29);

  n = 64u - i;
  if (len >= n) {
    memcpy(ctx->buf + i, p, n);
    md5_transform(ctx->state, ctx->buf);
    for (; n + 63 < len; n += 64)
      md5_transform(ctx->state, p + n);
    i = 0;
    p += n;
    len -= n;
  }
  if (len)
    memcpy(ctx->buf + i, p, len);
}

void MD5_Final(unsigned char digest[16], MD5_CTX *ctx) {
  static const unsigned char padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  unsigned char bits[8];
  unsigned int i, index, padLen;

  /* Encode count into bits (little-endian, low word first) */
  bits[0] = (unsigned char)(ctx->count[0]      );
  bits[1] = (unsigned char)(ctx->count[0] >>  8);
  bits[2] = (unsigned char)(ctx->count[0] >> 16);
  bits[3] = (unsigned char)(ctx->count[0] >> 24);
  bits[4] = (unsigned char)(ctx->count[1]      );
  bits[5] = (unsigned char)(ctx->count[1] >>  8);
  bits[6] = (unsigned char)(ctx->count[1] >> 16);
  bits[7] = (unsigned char)(ctx->count[1] >> 24);

  index = (unsigned int)((ctx->count[0] >> 3) & 63u);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5_Update(ctx, padding, padLen);
  MD5_Update(ctx, bits, 8);

  for (i = 0; i < 4; i++) {
    digest[i*4  ] = (unsigned char)(ctx->state[i]      );
    digest[i*4+1] = (unsigned char)(ctx->state[i] >>  8);
    digest[i*4+2] = (unsigned char)(ctx->state[i] >> 16);
    digest[i*4+3] = (unsigned char)(ctx->state[i] >> 24);
  }
}
