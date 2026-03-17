/*
 * Digest authentication helpers (RFC 2069).
 * Simplified digest auth: response = MD5(HA1:nonce:HA2)
 */
#include "common/digest_auth.h"

#include <string.h>

#include "common/md5.h"

void cvt_hex(const unsigned char *bin, HASHHEX hex) {
  for (int i = 0; i < DIGEST_HASHLEN; i++) {
    unsigned char j = (bin[i] >> 4) & 0xf;
    hex[i * 2]      = (char)(j <= 9 ? j + '0' : j + 'a' - 10);
    j               = bin[i] & 0xf;
    hex[i * 2 + 1]  = (char)(j <= 9 ? j + '0' : j + 'a' - 10);
  }
  hex[DIGEST_HASHHEXLEN] = '\0';
}

void digest_calc_ha1(const char *user, const char *realm, const char *password, HASHHEX out) {
  MD5_CTX ctx;
  HASH    ha1;
  MD5_Init(&ctx);
  if (user) MD5_Update(&ctx, (const unsigned char *)user, strlen(user));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (realm) MD5_Update(&ctx, (const unsigned char *)realm, strlen(realm));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (password) MD5_Update(&ctx, (const unsigned char *)password, strlen(password));
  MD5_Final(ha1, &ctx);
  cvt_hex(ha1, out);
}

void digest_calc_ha2(const char *method, const char *uri, HASHHEX out) {
  MD5_CTX ctx;
  HASH    ha2;
  MD5_Init(&ctx);
  if (method) MD5_Update(&ctx, (const unsigned char *)method, strlen(method));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (uri) MD5_Update(&ctx, (const unsigned char *)uri, strlen(uri));
  MD5_Final(ha2, &ctx);
  cvt_hex(ha2, out);
}

void digest_calc_response(HASHHEX ha1, const char *nonce, HASHHEX ha2, HASHHEX out) {
  MD5_CTX ctx;
  HASH    resphash;
  MD5_Init(&ctx);
  MD5_Update(&ctx, (const unsigned char *)ha1, DIGEST_HASHHEXLEN);
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (nonce) MD5_Update(&ctx, (const unsigned char *)nonce, strlen(nonce));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  MD5_Update(&ctx, (const unsigned char *)ha2, DIGEST_HASHHEXLEN);
  MD5_Final(resphash, &ctx);
  cvt_hex(resphash, out);
}
