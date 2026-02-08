/*
 * Minimal MD5 (RFC 1321) for Digest auth. No external crypto library.
 * API compatible with OpenSSL MD5_* for drop-in use.
 */
#ifndef UPBX_MD5_H
#define UPBX_MD5_H

#include <stddef.h>

typedef struct {
  unsigned int state[4];
  unsigned int count[2];
  unsigned char buf[64];
} MD5_CTX;

void MD5_Init(MD5_CTX *ctx);
void MD5_Update(MD5_CTX *ctx, const void *data, size_t len);
void MD5_Final(unsigned char digest[16], MD5_CTX *ctx);

#endif
