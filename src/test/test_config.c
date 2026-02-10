/*
 * Config parsing tests using finwo/assert.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "finwo/assert.h"
#include "config.h"

/* Write a temporary config file and return its path (caller frees). */
static char *write_temp_config(const char *content) {
  char path[] = "/tmp/upbx_test_config_XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0) return NULL;
  write(fd, content, strlen(content));
  close(fd);
  return strdup(path);
}

static const char *TEST_CONFIG =
  "[upbx]\n"
  "listen = 0.0.0.0:5060\n"
  "rtp_ports = 10000-20000\n"
  "locality = 3\n"
  "\n"
  "[trunk:mycarrier]\n"
  "host = sip.example.com\n"
  "port = 5060\n"
  "username = testuser\n"
  "password = testpass\n"
  "did = 15551234567\n"
  "cid = 15551234567\n"
  "\n"
  "[ext:200]\n"
  "secret = pass200\n"
  "name = Reception\n"
  "\n"
  "[ext:201]\n"
  "secret = pass201\n"
  "\n"
  "[plugin:myplug]\n"
  "exec = /usr/bin/myplug\n";

void test_config_load_basic(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  upbx_config c;
  config_init(&c);
  int rc = config_load(&c, path);
  ASSERT_EQUALS(0, rc);

  /* Check upbx section. */
  ASSERT_STRING_EQUALS("0.0.0.0:5060", c.listen);
  ASSERT_EQUALS(10000, c.rtp_port_low);
  ASSERT_EQUALS(20000, c.rtp_port_high);
  ASSERT_EQUALS(3, c.locality);

  config_free(&c);
  unlink(path);
  free(path);
}

void test_config_trunks(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  upbx_config c;
  config_init(&c);
  config_load(&c, path);

  ASSERT_EQUALS(1, (int)c.trunk_count);
  ASSERT_STRING_EQUALS("mycarrier", c.trunks[0].name);
  ASSERT_STRING_EQUALS("sip.example.com", c.trunks[0].host);
  ASSERT_STRING_EQUALS("testuser", c.trunks[0].username);
  ASSERT_STRING_EQUALS("testpass", c.trunks[0].password);
  ASSERT_EQUALS(1, (int)c.trunks[0].did_count);
  ASSERT_STRING_EQUALS("15551234567", c.trunks[0].dids[0]);
  ASSERT_STRING_EQUALS("15551234567", c.trunks[0].cid);

  config_free(&c);
  unlink(path);
  free(path);
}

void test_config_extensions(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  upbx_config c;
  config_init(&c);
  config_load(&c, path);

  ASSERT_EQUALS(2, (int)c.extension_count);
  ASSERT_STRING_EQUALS("200", c.extensions[0].number);
  ASSERT_STRING_EQUALS("pass200", c.extensions[0].secret);
  ASSERT_STRING_EQUALS("Reception", c.extensions[0].name);
  ASSERT_STRING_EQUALS("201", c.extensions[1].number);
  ASSERT_STRING_EQUALS("pass201", c.extensions[1].secret);

  config_free(&c);
  unlink(path);
  free(path);
}

void test_config_plugins(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  upbx_config c;
  config_init(&c);
  config_load(&c, path);

  ASSERT_EQUALS(1, (int)c.plugin_count);
  ASSERT_STRING_EQUALS("myplug", c.plugins[0].name);
  ASSERT_STRING_EQUALS("/usr/bin/myplug", c.plugins[0].exec);

  config_free(&c);
  unlink(path);
  free(path);
}

void test_config_missing_file(void) {
  upbx_config c;
  config_init(&c);
  int rc = config_load(&c, "/nonexistent/path/config.ini");
  ASSERT("missing file returns error", rc != 0);
  config_free(&c);
}

int main(void) {
  RUN(test_config_load_basic);
  RUN(test_config_trunks);
  RUN(test_config_extensions);
  RUN(test_config_plugins);
  RUN(test_config_missing_file);
  return TEST_REPORT();
}
