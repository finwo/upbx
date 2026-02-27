/*
 * Config parsing tests using finwo/assert.
 * Tests the new resp_object-based config system.
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
  
  resp_object *cfg = resp_array_init();
  int rc = config_load(cfg, path);
  ASSERT_EQUALS(0, rc);

  resp_object *upbx = resp_map_get(cfg, "upbx");
  ASSERT("upbx section exists", upbx != NULL);
  const char *listen = resp_map_get_string(upbx, "listen");
  ASSERT_STRING_EQUALS("0.0.0.0:5060", listen);
  
  resp_free(cfg);
  unlink(path);
  free(path);
}

void test_config_trunks(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  
  resp_object *cfg = resp_array_init();
  int rc = config_load(cfg, path);
  ASSERT_EQUALS(0, rc);

  int trunk_count = 0;
  for (size_t i = 0; i < cfg->u.arr.n; i++) {
    if (cfg->u.arr.elem[i].type == RESPT_BULK && 
        cfg->u.arr.elem[i].u.s &&
        strncmp(cfg->u.arr.elem[i].u.s, "trunk:", 6) == 0) {
      trunk_count++;
    }
  }
  ASSERT_EQUALS(1, trunk_count);

  resp_object *trunk = resp_map_get(cfg, "trunk:mycarrier");
  ASSERT("trunk:mycarrier exists", trunk != NULL);
  ASSERT_STRING_EQUALS("sip.example.com", resp_map_get_string(trunk, "host"));
  ASSERT_STRING_EQUALS("testuser", resp_map_get_string(trunk, "username"));

  resp_free(cfg);
  unlink(path);
  free(path);
}

void test_config_extensions(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  
  resp_object *cfg = resp_array_init();
  int rc = config_load(cfg, path);
  ASSERT_EQUALS(0, rc);

  int ext_count = 0;
  for (size_t i = 0; i < cfg->u.arr.n; i++) {
    if (cfg->u.arr.elem[i].type == RESPT_BULK && 
        cfg->u.arr.elem[i].u.s &&
        strncmp(cfg->u.arr.elem[i].u.s, "ext:", 4) == 0) {
      ext_count++;
    }
  }
  ASSERT_EQUALS(2, ext_count);

  resp_object *ext200 = resp_map_get(cfg, "ext:200");
  ASSERT("ext:200 exists", ext200 != NULL);
  ASSERT_STRING_EQUALS("pass200", resp_map_get_string(ext200, "secret"));
  ASSERT_STRING_EQUALS("Reception", resp_map_get_string(ext200, "name"));

  resp_free(cfg);
  unlink(path);
  free(path);
}

void test_config_plugins(void) {
  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);
  
  resp_object *cfg = resp_array_init();
  int rc = config_load(cfg, path);
  ASSERT_EQUALS(0, rc);

  int plugin_count = 0;
  for (size_t i = 0; i < cfg->u.arr.n; i++) {
    if (cfg->u.arr.elem[i].type == RESPT_BULK && 
        cfg->u.arr.elem[i].u.s &&
        strncmp(cfg->u.arr.elem[i].u.s, "plugin:", 7) == 0) {
      plugin_count++;
    }
  }
  ASSERT_EQUALS(1, plugin_count);

  resp_object *plug = resp_map_get(cfg, "plugin:myplug");
  ASSERT("plugin:myplug exists", plug != NULL);
  ASSERT_STRING_EQUALS("/usr/bin/myplug", resp_map_get_string(plug, "exec"));

  resp_free(cfg);
  unlink(path);
  free(path);
}

void test_config_missing_file(void) {
  resp_object *cfg = resp_array_init();
  int rc = config_load(cfg, "/nonexistent/path/config.ini");
  ASSERT("missing file returns error", rc != 0);
  resp_free(cfg);
}

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

int main(void) {
  RUN(test_config_load_basic);
  RUN(test_config_trunks);
  RUN(test_config_extensions);
  RUN(test_config_plugins);
  RUN(test_config_missing_file);
  RUN(test_config_sections_list_path);
  RUN(test_config_section_get_path);
  RUN(test_config_key_get_path);
  return TEST_REPORT();
}
