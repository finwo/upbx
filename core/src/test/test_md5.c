/*
 * MD5 tests using finwo/assert.
 * RFC 1321 and standard test vectors.
 */
#include <stdio.h>
#include <string.h>
#include "finwo/assert.h"
#include "common/md5.h"

static void md5_hex(const char *input, size_t len, char hex[33]) {
  MD5_CTX ctx;
  unsigned char digest[16];
  MD5_Init(&ctx);
  MD5_Update(&ctx, input, len);
  MD5_Final(digest, &ctx);
  for (int i = 0; i < 16; i++)
    sprintf(hex + i * 2, "%02x", digest[i]);
  hex[32] = '\0';
}

void test_md5_empty(void) {
  char hex[33];
  md5_hex("", 0, hex);
  ASSERT_STRING_EQUALS("d41d8cd98f00b204e9800998ecf8427e", hex);
}

void test_md5_a(void) {
  char hex[33];
  md5_hex("a", 1, hex);
  ASSERT_STRING_EQUALS("0cc175b9c0f1b6a831c399e269772661", hex);
}

void test_md5_aa(void) {
  char hex[33];
  md5_hex("aa", 2, hex);
  ASSERT_STRING_EQUALS("4124bc0a9335c27f086f24ba207a4912", hex);
}

void test_md5_abc(void) {
  char hex[33];
  md5_hex("abc", 3, hex);
  ASSERT_STRING_EQUALS("900150983cd24fb0d6963f7d28e17f72", hex);
}

void test_md5_message_digest(void) {
  char hex[33];
  md5_hex("message digest", 14, hex);
  ASSERT_STRING_EQUALS("f96b697d7cb7938d525a2f31aaf161d0", hex);
}

void test_md5_alphabet(void) {
  char hex[33];
  md5_hex("abcdefghijklmnopqrstuvwxyz", 26, hex);
  ASSERT_STRING_EQUALS("c3fcd3d76192e4007dfb496cca67e13b", hex);
}

void test_md5_alphanumeric(void) {
  char hex[33];
  md5_hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, hex);
  ASSERT_STRING_EQUALS("d174ab98d277d9f5a5611c2c9f419d9f", hex);
}

void test_md5_numeric(void) {
  char hex[33];
  md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, hex);
  ASSERT_STRING_EQUALS("57edf4a22be3c955ac49da2e2107b67a", hex);
}

int main(void) {
  RUN(test_md5_empty);
  RUN(test_md5_a);
  RUN(test_md5_aa);
  RUN(test_md5_abc);
  RUN(test_md5_message_digest);
  RUN(test_md5_alphabet);
  RUN(test_md5_alphanumeric);
  RUN(test_md5_numeric);
  return TEST_REPORT();
}
