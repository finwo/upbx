#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/resp.h"
#include "domain/config.h"
#include "domain/pbx/group.h"
#include "domain/pbx/registration.h"
#include "finwo/assert.h"
#include "infrastructure/config.h"

static char *write_temp_config(const char *content) {
  char path[] = "/tmp/upbx_test_group_XXXXXX";
  int  fd     = mkstemp(path);
  if (fd < 0) return NULL;
  write(fd, content, strlen(content));
  close(fd);
  return strdup(path);
}

static const char *TEST_CONFIG =
    "[upbx]\n"
    "address = :5060\n"
    "\n"
    "[group:2]\n"
    "allow_outgoing_cross_group = true\n"
    "\n"
    "[group:3]\n"
    "allow_outgoing_cross_group = false\n"
    "\n"
    "[group:08540]\n"
    "allow_incoming_cross_group = false\n"
    "\n";

void test_group_find_for_extension(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);

  domain_cfg = resp_array_init();
  config_load(domain_cfg, path);

  group_config_init();

  ASSERT_STRING_EQUALS("2", group_find_for_extension("200"));
  ASSERT_STRING_EQUALS("2", group_find_for_extension("201"));
  ASSERT_STRING_EQUALS("2", group_find_for_extension("299"));
  ASSERT_STRING_EQUALS("3", group_find_for_extension("300"));
  ASSERT_STRING_EQUALS("3", group_find_for_extension("399"));
  ASSERT_STRING_EQUALS("08540", group_find_for_extension("08540100"));
  ASSERT_STRING_EQUALS("08540", group_find_for_extension("08540999"));
  ASSERT("no group for unknown", group_find_for_extension("999") == NULL);

  group_config_free();
  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(path);
  free(path);
}

void test_group_cross_group_permissions(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);

  domain_cfg = resp_array_init();
  config_load(domain_cfg, path);

  group_config_init();

  ASSERT("group 2 incoming default true", group_get_allow_incoming_cross_group("2") == true);
  ASSERT("group 2 outgoing true", group_get_allow_outgoing_cross_group("2") == true);
  ASSERT("group 3 incoming default true", group_get_allow_incoming_cross_group("3") == true);
  ASSERT("group 3 outgoing false", group_get_allow_outgoing_cross_group("3") == false);
  ASSERT("group 08540 incoming false", group_get_allow_incoming_cross_group("08540") == false);
  ASSERT("group 08540 outgoing default false", group_get_allow_outgoing_cross_group("08540") == false);
  ASSERT("unknown group incoming default true", group_get_allow_incoming_cross_group("999") == true);
  ASSERT("unknown group outgoing default false", group_get_allow_outgoing_cross_group("999") == false);

  group_config_free();
  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(path);
  free(path);
}

int main(void) {
  RUN(test_group_find_for_extension);
  RUN(test_group_cross_group_permissions);
  return TEST_REPORT();
}
