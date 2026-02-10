/*
 * Digest auth tests using finwo/assert.
 * Test vectors derived from RFC 2617 Section 3.5.
 */
#include <string.h>
#include "finwo/assert.h"
#include "common/digest_auth.h"

/* RFC 2617 Section 3.5 example:
 *   user = "Mufasa"
 *   realm = "testrealm@host.com"
 *   password = "Circle Of Life"
 *   nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
 *   method = "GET"
 *   uri = "/dir/index.html"
 *   qop = "auth"
 *   nc = "00000001"
 *   cnonce = "0a4f113b"
 *
 *   HA1 = MD5("Mufasa:testrealm@host.com:Circle Of Life") = 939e7578ed9e3c518a452acee763bce9
 *   HA2 = MD5("GET:/dir/index.html") = 39aff3a2bab6126f332b942af5e6afc3
 *   response = MD5("939e7578ed9e3c518a452acee763bce9:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:39aff3a2bab6126f332b942af5e6afc3")
 *            = 6629fae49393a05397450978507c4ef1
 */

void test_digest_calc_ha1(void) {
  HASHHEX ha1;
  digest_calc_ha1("md5", "Mufasa", "testrealm@host.com", "Circle Of Life", NULL, NULL, ha1);
  ASSERT_STRING_EQUALS("939e7578ed9e3c518a452acee763bce9", (const char *)ha1);
}

void test_digest_calc_response_with_qop(void) {
  HASHHEX ha1;
  digest_calc_ha1("md5", "Mufasa", "testrealm@host.com", "Circle Of Life", NULL, NULL, ha1);

  HASHHEX response;
  HASHHEX hentity = "";
  digest_calc_response(ha1, "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b",
    "auth", "GET", "/dir/index.html", hentity, response);
  ASSERT_STRING_EQUALS("6629fae49393a05397450978507c4ef1", (const char *)response);
}

void test_digest_calc_response_without_qop(void) {
  /* RFC 2069 style: response = MD5(HA1:nonce:HA2) */
  HASHHEX ha1;
  digest_calc_ha1("md5", "Mufasa", "testrealm@host.com", "Circle Of Life", NULL, NULL, ha1);

  HASHHEX response;
  HASHHEX hentity = "";
  digest_calc_response(ha1, "dcd98b7102dd2f0e8b11d0f600bfb0c093", NULL, NULL,
    NULL, "GET", "/dir/index.html", hentity, response);

  /* Manually compute: MD5("939e7578ed9e3c518a452acee763bce9:dcd98b7102dd2f0e8b11d0f600bfb0c093:39aff3a2bab6126f332b942af5e6afc3")
   * = 670fd8c2df070c60b045671b8b24ff02 */
  ASSERT_STRING_EQUALS("670fd8c2df070c60b045671b8b24ff02", (const char *)response);
}

void test_cvt_hex(void) {
  unsigned char bin[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  HASHHEX hex;
  cvt_hex(bin, hex);
  ASSERT_STRING_EQUALS("000102030405060708090a0b0c0d0e0f", (const char *)hex);
}

int main(void) {
  RUN(test_cvt_hex);
  RUN(test_digest_calc_ha1);
  RUN(test_digest_calc_response_with_qop);
  RUN(test_digest_calc_response_without_qop);
  return TEST_REPORT();
}
