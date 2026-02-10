/*
 * Digest authentication helpers (RFC 2617 / RFC 2069).
 * Unified from duplicated code in sip_server.c and trunk_reg.c.
 */
#include "common/digest_auth.h"
#include "common/md5.h"
#include <string.h>
#include <strings.h>

void cvt_hex(const unsigned char *bin, HASHHEX hex) {
  for (int i = 0; i < DIGEST_HASHLEN; i++) {
    unsigned char j = (bin[i] >> 4) & 0xf;
    hex[i * 2] = (char)(j <= 9 ? j + '0' : j + 'a' - 10);
    j = bin[i] & 0xf;
    hex[i * 2 + 1] = (char)(j <= 9 ? j + '0' : j + 'a' - 10);
  }
  hex[DIGEST_HASHHEXLEN] = '\0';
}

void digest_calc_ha1(const char *alg, const char *user, const char *realm,
    const char *password, const char *nonce, const char *cnonce, HASHHEX out) {
  MD5_CTX ctx;
  HASH ha1;
  MD5_Init(&ctx);
  if (user) MD5_Update(&ctx, (const unsigned char *)user, strlen(user));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (realm) MD5_Update(&ctx, (const unsigned char *)realm, strlen(realm));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (password) MD5_Update(&ctx, (const unsigned char *)password, strlen(password));
  MD5_Final(ha1, &ctx);
  if (alg && strcasecmp(alg, "md5-sess") == 0) {
    MD5_Init(&ctx);
    MD5_Update(&ctx, ha1, DIGEST_HASHLEN);
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (nonce) MD5_Update(&ctx, (const unsigned char *)nonce, strlen(nonce));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (cnonce) MD5_Update(&ctx, (const unsigned char *)cnonce, strlen(cnonce));
    MD5_Final(ha1, &ctx);
  }
  cvt_hex(ha1, out);
}

void digest_calc_response(HASHHEX ha1, const char *nonce, const char *nc,
    const char *cnonce, const char *qop, const char *method, const char *uri,
    HASHHEX hentity, HASHHEX out) {
  MD5_CTX ctx;
  HASH ha2, resphash;
  HASHHEX ha2hex;

  /* HA2 = MD5(method:uri) or MD5(method:uri:MD5(entity-body)) for qop=auth-int */
  MD5_Init(&ctx);
  if (method) MD5_Update(&ctx, (const unsigned char *)method, strlen(method));
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (uri) MD5_Update(&ctx, (const unsigned char *)uri, strlen(uri));
  if (qop && strcasecmp(qop, "auth-int") == 0 && hentity) {
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    MD5_Update(&ctx, (const unsigned char *)hentity, DIGEST_HASHHEXLEN);
  }
  MD5_Final(ha2, &ctx);
  cvt_hex(ha2, ha2hex);

  /* response = MD5(HA1:nonce[:nc:cnonce:qop]:HA2) */
  MD5_Init(&ctx);
  MD5_Update(&ctx, (const unsigned char *)ha1, DIGEST_HASHHEXLEN);
  MD5_Update(&ctx, (const unsigned char *)":", 1);
  if (nonce) MD5_Update(&ctx, (const unsigned char *)nonce, strlen(nonce));
  if (qop && *qop) {
    /* RFC 2617 with qop: HA1:nonce:nc:cnonce:qop:HA2 */
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (nc) MD5_Update(&ctx, (const unsigned char *)nc, strlen(nc));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    if (cnonce) MD5_Update(&ctx, (const unsigned char *)cnonce, strlen(cnonce));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
    MD5_Update(&ctx, (const unsigned char *)qop, strlen(qop));
    MD5_Update(&ctx, (const unsigned char *)":", 1);
  } else {
    /* RFC 2069: HA1:nonce:HA2 */
    MD5_Update(&ctx, (const unsigned char *)":", 1);
  }
  MD5_Update(&ctx, (const unsigned char *)ha2hex, DIGEST_HASHHEXLEN);
  MD5_Final(resphash, &ctx);
  cvt_hex(resphash, out);
}
