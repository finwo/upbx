/*
 * Single-file test program for MD5 implementation.
 * RFC 1321 and standard test vectors. Build: make md5_test  (or link with md5.c).
 */
#include <stdio.h>
#include <string.h>
#include "AppModule/md5.h"

static int test_one(const char *input, size_t len, const char *expected_hex) {
  MD5_CTX ctx;
  unsigned char digest[16];
  char hex[33];
  int i;

  MD5_Init(&ctx);
  MD5_Update(&ctx, input, len);
  MD5_Final(digest, &ctx);

  for (i = 0; i < 16; i++)
    sprintf(hex + i * 2, "%02x", digest[i]);
  hex[32] = '\0';

  if (strcmp(hex, expected_hex) != 0) {
    printf("FAIL: \"%.*s\"\n  got      %s\n  expected %s\n", (int)len, input, hex, expected_hex);
    return 0;
  }
  printf("OK: \"%.*s\" -> %s\n", (int)len, input, hex);
  return 1;
}

int main(void) {
  int n = 0, ok = 0;

  /* RFC 1321 and common test vectors */
  #define T(INPUT, EXPECTED) do { n++; if (test_one(INPUT, sizeof(INPUT) - 1, EXPECTED)) ok++; } while (0)

  T("", "d41d8cd98f00b204e9800998ecf8427e");
  T("a", "0cc175b9c0f1b6a831c399e269772661");
  T("aa", "4124bc0a9335c27f086f24ba207a4912");  /* 2 bytes */
  T("abc", "900150983cd24fb0d6963f7d28e17f72");
  T("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
  T("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
  T("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f");
  T("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a");

  #undef T

  printf("%d/%d tests passed\n", ok, n);
  return (ok == n) ? 0 : 1;
}
