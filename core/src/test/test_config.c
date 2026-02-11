/*
 * Config parsing tests using finwo/assert.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "finwo/assert.h"
#include "config.h"
#include "RespModule/resp.h"

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

/* --- Live config API tests --- */
void test_config_sections_list_path(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  resp_object *arr = config_sections_list_path(path);
  ASSERT("sections list non-NULL", arr != NULL);
  ASSERT_EQUALS(RESPT_ARRAY, arr->type);
  ASSERT("has sections", arr->u.arr.n >= 4);
  int has_upbx = 0, has_trunk = 0, has_ext = 0, has_plugin = 0;
  for (size_t i = 0; i < arr->u.arr.n; i++) {
    resp_object *e = &arr->u.arr.elem[i];
    if (e->type == RESPT_BULK && e->u.s) {
      if (strcmp(e->u.s, "upbx") == 0) has_upbx = 1;
      if (strncmp(e->u.s, "trunk:", 6) == 0) has_trunk = 1;
      if (strncmp(e->u.s, "ext:", 4) == 0) has_ext = 1;
      if (strncmp(e->u.s, "plugin:", 7) == 0) has_plugin = 1;
    }
  }
  ASSERT("has upbx section", has_upbx);
  ASSERT("has trunk section", has_trunk);
  ASSERT("has ext section", has_ext);
  ASSERT("has plugin section", has_plugin);
  resp_free(arr);
  unlink(path);
  free(path);
}

void test_config_section_get_path(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  resp_object *map = config_section_get_path(path, "upbx");
  ASSERT("section get non-NULL", map != NULL);
  ASSERT_EQUALS(RESPT_ARRAY, map->type);
  const char *listen = resp_map_get_string(map, "listen");
  ASSERT("listen key present", listen != NULL);
  ASSERT_STRING_EQUALS("0.0.0.0:5060", listen);
  resp_free(map);
  map = config_section_get_path(path, "ext:200");
  ASSERT("ext:200 section non-NULL", map != NULL);
  ASSERT_STRING_EQUALS("pass200", resp_map_get_string(map, "secret"));
  ASSERT_STRING_EQUALS("Reception", resp_map_get_string(map, "name"));
  resp_free(map);
  unlink(path);
  free(path);
}

void test_config_key_get_path(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  resp_object *v = config_key_get_path(path, "upbx", "listen");
  ASSERT("key get non-NULL", v != NULL);
  ASSERT_EQUALS(RESPT_BULK, v->type);
  ASSERT_STRING_EQUALS("0.0.0.0:5060", v->u.s);
  resp_free(v);
  v = config_key_get_path(path, "upbx", "locality");
  ASSERT("locality key non-NULL", v != NULL);
  ASSERT_EQUALS(RESPT_INT, v->type);
  ASSERT_EQUALS(3, (int)v->u.i);
  resp_free(v);
  unlink(path);
  free(path);
}

void test_config_default_getters(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  config_set_path(path);
  resp_object *arr = config_sections_list();
  ASSERT("default sections list non-NULL", arr != NULL);
  ASSERT_EQUALS(RESPT_ARRAY, arr->type);
  resp_free(arr);
  resp_object *map = config_section_get("upbx");
  ASSERT("default section get non-NULL", map != NULL);
  ASSERT_STRING_EQUALS("0.0.0.0:5060", resp_map_get_string(map, "listen"));
  resp_free(map);
  resp_object *kv = config_key_get("upbx", "listen");
  ASSERT("default key get non-NULL", kv != NULL);
  ASSERT_STRING_EQUALS("0.0.0.0:5060", kv->u.s);
  resp_free(kv);
  config_set_path(NULL);
  ASSERT("sections_list with no path returns NULL", config_sections_list() == NULL);
  unlink(path);
  free(path);
}

int main(void) {
  RUN(test_config_load_basic);
  RUN(test_config_trunks);
  RUN(test_config_extensions);
  RUN(test_config_plugins);
  RUN(test_config_missing_file);
  RUN(test_config_sections_list_path);
  RUN(test_config_section_get_path);
  RUN(test_config_key_get_path);
  RUN(test_config_default_getters);
  return TEST_REPORT();
}
