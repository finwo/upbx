/*
 * Digest authentication helpers (RFC 2617 / RFC 2069).
 * Shared between SIP server (extension auth) and trunk registration (client auth).
 */
#ifndef UPBX_DIGEST_AUTH_H
#define UPBX_DIGEST_AUTH_H

#define DIGEST_HASHLEN    16
#define DIGEST_HASHHEXLEN 32

typedef unsigned char HASH[DIGEST_HASHLEN];
typedef unsigned char HASHHEX[DIGEST_HASHHEXLEN + 1];

/* Convert raw 16-byte hash to 32-char lowercase hex string (NUL-terminated). */
void cvt_hex(const unsigned char *bin, HASHHEX hex);

/* Compute HA1 = MD5(user:realm:password); if alg is "md5-sess", also folds in nonce:cnonce. */
void digest_calc_ha1(const char *alg, const char *user, const char *realm,
    const char *password, const char *nonce, const char *cnonce, HASHHEX out);

/* Compute request-digest per RFC 2617 (with qop) or RFC 2069 (without qop).
 * ha1 must already be computed via digest_calc_ha1. hentity is used only when qop="auth-int". */
void digest_calc_response(HASHHEX ha1, const char *nonce, const char *nc,
    const char *cnonce, const char *qop, const char *method, const char *uri,
    HASHHEX hentity, HASHHEX out);

#endif
