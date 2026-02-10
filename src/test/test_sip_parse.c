/*
 * SIP parse tests using finwo/assert.
 */
#include <string.h>
#include <stdbool.h>
#include "finwo/assert.h"
#include "AppModule/sip_parse.h"

/* A minimal INVITE request for testing. */
static const char *INVITE_REQ =
  "INVITE sip:200@10.0.0.1:5060 SIP/2.0\r\n"
  "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-524287-1\r\n"
  "From: <sip:100@10.0.0.1>;tag=abcdef\r\n"
  "To: <sip:200@10.0.0.1>\r\n"
  "Call-ID: testcall@10.0.0.2\r\n"
  "CSeq: 1 INVITE\r\n"
  "Contact: <sip:100@10.0.0.2:5060>\r\n"
  "Max-Forwards: 70\r\n"
  "Content-Length: 0\r\n"
  "\r\n";

/* A minimal 200 OK response for testing. */
static const char *RESPONSE_200 =
  "SIP/2.0 200 OK\r\n"
  "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-524287-1\r\n"
  "From: <sip:100@10.0.0.1>;tag=abcdef\r\n"
  "To: <sip:200@10.0.0.1>;tag=ghijkl\r\n"
  "Call-ID: testcall@10.0.0.2\r\n"
  "CSeq: 1 INVITE\r\n"
  "Content-Length: 0\r\n"
  "\r\n";

void test_sip_is_request(void) {
  ASSERT("INVITE is a request", sip_is_request(INVITE_REQ, strlen(INVITE_REQ)));
  ASSERT("200 OK is not a request", !sip_is_request(RESPONSE_200, strlen(RESPONSE_200)));
}

void test_sip_response_status_code(void) {
  ASSERT_EQUALS(200, sip_response_status_code(RESPONSE_200, strlen(RESPONSE_200)));
  ASSERT_EQUALS(0, sip_response_status_code(INVITE_REQ, strlen(INVITE_REQ)));
}

void test_sip_header_get(void) {
  const char *val = NULL;
  size_t val_len = 0;
  int found = sip_header_get(INVITE_REQ, strlen(INVITE_REQ), "Call-ID", &val, &val_len);
  ASSERT("found Call-ID", found);
  ASSERT("Call-ID value correct", val_len == strlen("testcall@10.0.0.2") && strncmp(val, "testcall@10.0.0.2", val_len) == 0);
}

void test_sip_header_copy(void) {
  char buf[256];
  int found = sip_header_copy(INVITE_REQ, strlen(INVITE_REQ), "CSeq", buf, sizeof(buf));
  ASSERT("found CSeq", found);
  ASSERT_STRING_EQUALS("1 INVITE", buf);
}

void test_sip_request_uri_user(void) {
  char user[64];
  int ok = sip_request_uri_user(INVITE_REQ, strlen(INVITE_REQ), user, sizeof(user));
  ASSERT("got user", ok);
  ASSERT_STRING_EQUALS("200", user);
}

void test_sip_request_uri_host_port(void) {
  char host[128], port[32];
  int ok = sip_request_uri_host_port(INVITE_REQ, strlen(INVITE_REQ), host, sizeof(host), port, sizeof(port));
  ASSERT("got host:port", ok);
  ASSERT_STRING_EQUALS("10.0.0.1", host);
  ASSERT_STRING_EQUALS("5060", port);
}

void test_sip_format_request_uri(void) {
  char out[256];
  int ok = sip_format_request_uri("alice", "example.com", "5060", out, sizeof(out));
  ASSERT("format ok", ok);
  /* Port 5060 should be omitted from the formatted URI. */
  ASSERT_STRING_EQUALS("sip:alice@example.com", out);
}

void test_sip_format_request_uri_with_port(void) {
  char out[256];
  int ok = sip_format_request_uri("bob", "example.com", "5070", out, sizeof(out));
  ASSERT("format ok", ok);
  ASSERT_STRING_EQUALS("sip:bob@example.com:5070", out);
}

void test_sip_rewrite_request_uri(void) {
  char out[2048];
  int len = sip_rewrite_request_uri(INVITE_REQ, strlen(INVITE_REQ), "sip:300@10.0.0.3:5060", out, sizeof(out));
  ASSERT("rewrite ok", len > 0);
  out[len] = '\0';
  ASSERT("new URI present", strstr(out, "INVITE sip:300@10.0.0.3:5060 SIP/2.0") != NULL);
}

void test_sip_prepend_via(void) {
  char out[2048];
  int len = sip_prepend_via(INVITE_REQ, strlen(INVITE_REQ), "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-new", out, sizeof(out));
  ASSERT("prepend ok", len > 0);
  out[len] = '\0';
  /* The new Via should appear before the old one. */
  char *first_via = strstr(out, "Via:");
  ASSERT("found via", first_via != NULL);
  ASSERT("new via first", strstr(first_via, "10.0.0.9") != NULL);
}

void test_sip_strip_top_via(void) {
  /* First prepend an extra Via, then strip it to verify round-trip. */
  char with_via[2048], out[2048];
  int len1 = sip_prepend_via(INVITE_REQ, strlen(INVITE_REQ), "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-new", with_via, sizeof(with_via));
  ASSERT("prepend ok", len1 > 0);
  int len2 = sip_strip_top_via(with_via, (size_t)len1, out, sizeof(out));
  ASSERT("strip ok", len2 > 0);
  out[len2] = '\0';
  /* Should be back to original Via only. */
  ASSERT("original via remains", strstr(out, "Via: SIP/2.0/UDP 10.0.0.2:5060") != NULL);
  ASSERT("added via removed", strstr(out, "10.0.0.9") == NULL);
}

void test_sip_security_check_raw(void) {
  /* Valid SIP message should pass. */
  char buf[2048];
  strncpy(buf, INVITE_REQ, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  ASSERT("valid message passes", sip_security_check_raw(buf, strlen(buf)));
}

void test_looks_like_sip(void) {
  ASSERT("INVITE looks like SIP", looks_like_sip(INVITE_REQ, strlen(INVITE_REQ)));
  ASSERT("200 OK looks like SIP", looks_like_sip(RESPONSE_200, strlen(RESPONSE_200)));
  ASSERT("random data is not SIP", !looks_like_sip("hello world", 11));
  ASSERT("too short is not SIP", !looks_like_sip("SIP/2", 5));
}

int main(void) {
  RUN(test_sip_is_request);
  RUN(test_sip_response_status_code);
  RUN(test_sip_header_get);
  RUN(test_sip_header_copy);
  RUN(test_sip_request_uri_user);
  RUN(test_sip_request_uri_host_port);
  RUN(test_sip_format_request_uri);
  RUN(test_sip_format_request_uri_with_port);
  RUN(test_sip_rewrite_request_uri);
  RUN(test_sip_prepend_via);
  RUN(test_sip_strip_top_via);
  RUN(test_sip_security_check_raw);
  RUN(test_looks_like_sip);
  return TEST_REPORT();
}
