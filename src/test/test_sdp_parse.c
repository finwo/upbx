/*
 * SDP parse tests using finwo/assert.
 */
#include <string.h>
#include "finwo/assert.h"
#include "AppModule/sdp_parse.h"

static const char *SIMPLE_SDP =
  "v=0\r\n"
  "o=- 0 0 IN IP4 192.168.1.100\r\n"
  "s=-\r\n"
  "c=IN IP4 192.168.1.100\r\n"
  "t=0 0\r\n"
  "m=audio 4000 RTP/AVP 0 8 101\r\n"
  "a=rtpmap:0 PCMU/8000\r\n"
  "a=rtpmap:8 PCMA/8000\r\n"
  "a=rtpmap:101 telephone-event/8000\r\n";

static const char *TWO_MEDIA_SDP =
  "v=0\r\n"
  "o=- 0 0 IN IP4 10.0.0.1\r\n"
  "s=-\r\n"
  "c=IN IP4 10.0.0.1\r\n"
  "t=0 0\r\n"
  "m=audio 5000 RTP/AVP 0\r\n"
  "m=video 5002 RTP/AVP 96\r\n"
  "c=IN IP4 10.0.0.2\r\n";

void test_sdp_parse_simple(void) {
  sdp_media_t media[SDP_MAX_MEDIA];
  size_t n = 0;
  int rc = sdp_parse_media(SIMPLE_SDP, strlen(SIMPLE_SDP), media, SDP_MAX_MEDIA, &n);
  ASSERT_EQUALS(0, rc);
  ASSERT_EQUALS(1, (int)n);
  ASSERT_STRING_EQUALS("192.168.1.100", media[0].ip);
  ASSERT_EQUALS(4000, media[0].port);
}

void test_sdp_parse_two_media(void) {
  sdp_media_t media[SDP_MAX_MEDIA];
  size_t n = 0;
  int rc = sdp_parse_media(TWO_MEDIA_SDP, strlen(TWO_MEDIA_SDP), media, SDP_MAX_MEDIA, &n);
  ASSERT_EQUALS(0, rc);
  ASSERT_EQUALS(2, (int)n);
  ASSERT_EQUALS(5000, media[0].port);
  ASSERT_STRING_EQUALS("10.0.0.1", media[0].ip);
  ASSERT_EQUALS(5002, media[1].port);
  /* Second m= section has its own c= line, overriding session-level. */
  ASSERT_STRING_EQUALS("10.0.0.2", media[1].ip);
}

void test_sdp_parse_no_media(void) {
  const char *sdp = "v=0\r\ns=-\r\n";
  sdp_media_t media[SDP_MAX_MEDIA];
  size_t n = 0;
  int rc = sdp_parse_media(sdp, strlen(sdp), media, SDP_MAX_MEDIA, &n);
  ASSERT_EQUALS(-1, rc);
  ASSERT_EQUALS(0, (int)n);
}

void test_sdp_rewrite(void) {
  char out[2048];
  int len = sdp_rewrite_addr(SIMPLE_SDP, strlen(SIMPLE_SDP), "10.20.30.40", 6000, out, sizeof(out));
  ASSERT("rewrite returns positive length", len > 0);

  /* Parse the rewritten SDP to verify the changes. */
  sdp_media_t media[SDP_MAX_MEDIA];
  size_t n = 0;
  int rc = sdp_parse_media(out, (size_t)len, media, SDP_MAX_MEDIA, &n);
  ASSERT_EQUALS(0, rc);
  ASSERT_EQUALS(1, (int)n);
  ASSERT_STRING_EQUALS("10.20.30.40", media[0].ip);
  ASSERT_EQUALS(6000, media[0].port);
}

void test_sdp_rewrite_preserves_attributes(void) {
  char out[2048];
  int len = sdp_rewrite_addr(SIMPLE_SDP, strlen(SIMPLE_SDP), "1.2.3.4", 9999, out, sizeof(out));
  ASSERT("rewrite returns positive length", len > 0);
  out[len] = '\0';
  /* The a= lines and codec list should survive unchanged. */
  ASSERT("contains rtpmap:0", strstr(out, "a=rtpmap:0 PCMU/8000") != NULL);
  ASSERT("contains RTP/AVP 0 8 101", strstr(out, "RTP/AVP 0 8 101") != NULL);
}

int main(void) {
  RUN(test_sdp_parse_simple);
  RUN(test_sdp_parse_two_media);
  RUN(test_sdp_parse_no_media);
  RUN(test_sdp_rewrite);
  RUN(test_sdp_rewrite_preserves_attributes);
  return TEST_REPORT();
}
