/*
 * Digest authentication helpers (RFC 2069).
 * Simplified digest auth: response = MD5(HA1:nonce:HA2)
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

/* HA1 = MD5(username:realm:password) */
void digest_calc_ha1(const char *user, const char *realm, const char *password, HASHHEX out);

/* HA2 = MD5(method:uri) */
void digest_calc_ha2(const char *method, const char *uri, HASHHEX out);

/* response = MD5(HA1:nonce:HA2) */
void digest_calc_response(HASHHEX ha1, const char *nonce, HASHHEX ha2, HASHHEX out);

#endif
