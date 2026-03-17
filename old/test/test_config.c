#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "common/resp.h"
#include "domain/config.h"
#include "finwo/assert.h"
#include "infrastructure/config.h"

static char *write_temp_config(const char *content) {
  char path[] = "/tmp/upbx_test_config_XXXXXX";
  int  fd     = mkstemp(path);
  if (fd < 0) return NULL;
  write(fd, content, strlen(content));
  close(fd);
  return strdup(path);
}

static char *create_temp_dir(void) {
  char path[] = "/tmp/upbx_test_config_dir_XXXXXX";
  if (mkdtemp(path) == NULL) return NULL;
  return strdup(path);
}

static int write_file(const char *dir, const char *filename, const char *content) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", dir, filename);
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  fwrite(content, 1, strlen(content), f);
  fclose(f);
  return 0;
}

static void test_config_load_single_file(void) {
  const char *TEST_CONFIG =
      "[upbx]\n"
      "address = :5060\n"
      "listen = 127.0.0.1:5061\n"
      "\n"
      "[group:100]\n"
      "allow_outgoing_cross_group = true\n"
      "\n";

  char *path = write_temp_config(TEST_CONFIG);
  ASSERT("temp file created", path != NULL);

  domain_cfg = resp_array_init();
  int r = config_load(domain_cfg, path);
  ASSERT("config_load returned 0", r == 0);

  resp_object *sec = resp_map_get(domain_cfg, "upbx");
  ASSERT("upbx section exists", sec != NULL);
  ASSERT("upbx section is array", sec->type == RESPT_ARRAY);

  resp_object *arr = resp_map_get(sec, "address");
  ASSERT("address key exists", arr != NULL);

  resp_object *listen_arr = resp_map_get(sec, "listen");
  ASSERT("listen key exists", listen_arr != NULL);

  resp_object *grp = resp_map_get(domain_cfg, "group:100");
  ASSERT("group:100 section exists", grp != NULL);

  resp_object *allow = resp_map_get(grp, "allow_outgoing_cross_group");
  ASSERT("allow_outgoing_cross_group key exists", allow != NULL);

  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(path);
  free(path);
}

static void test_config_load_directory(void) {
  char *dir = create_temp_dir();
  ASSERT("temp dir created", dir != NULL);

  write_file(dir, "01_first.conf",
             "[section_a]\n"
             "key_a = value_a\n"
             "\n");

  write_file(dir, "02_second.conf",
             "[section_b]\n"
             "key_b = value_b\n"
             "\n");

  domain_cfg = resp_array_init();
  int r = config_load(domain_cfg, dir);
  ASSERT("config_load returned 0", r == 0);

  resp_object *sec_a = resp_map_get(domain_cfg, "section_a");
  ASSERT("section_a exists", sec_a != NULL);

  resp_object *sec_b = resp_map_get(domain_cfg, "section_b");
  ASSERT("section_b exists", sec_b != NULL);

  resp_object *key_a = resp_map_get(sec_a, "key_a");
  ASSERT("key_a exists", key_a != NULL);

  resp_object *key_b = resp_map_get(sec_b, "key_b");
  ASSERT("key_b exists", key_b != NULL);

  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(dir);
  free(dir);
}

static void test_config_load_directory_recursive(void) {
  char *dir = create_temp_dir();
  ASSERT("temp dir created", dir != NULL);

  char subdir[1024];
  snprintf(subdir, sizeof(subdir), "%s/subdir", dir);
  mkdir(subdir, 0755);

  write_file(dir, "01_root.conf",
             "[root]\n"
             "key = root_value\n"
             "\n");

  write_file(subdir, "02_nested.conf",
             "[nested]\n"
             "key = nested_value\n"
             "\n");

  domain_cfg = resp_array_init();
  int r = config_load(domain_cfg, dir);
  ASSERT("config_load returned 0", r == 0);

  resp_object *root_sec = resp_map_get(domain_cfg, "root");
  ASSERT("root section exists", root_sec != NULL);

  resp_object *nested_sec = resp_map_get(domain_cfg, "nested");
  ASSERT("nested section exists", nested_sec != NULL);

  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(dir);
  free(dir);
}

static void test_config_load_directory_ignores_non_conf(void) {
  char *dir = create_temp_dir();
  ASSERT("temp dir created", dir != NULL);

  write_file(dir, "01_valid.conf",
             "[valid]\n"
             "key = value\n"
             "\n");

  write_file(dir, "readme.txt", "This is not a config file");

  write_file(dir, "script.sh", "#!/bin/bash\necho test");

  domain_cfg = resp_array_init();
  int r = config_load(domain_cfg, dir);
  ASSERT("config_load returned 0", r == 0);

  resp_object *valid_sec = resp_map_get(domain_cfg, "valid");
  ASSERT("valid section exists", valid_sec != NULL);

  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(dir);
  free(dir);
}

static void test_config_load_directory_empty(void) {
  char *dir = create_temp_dir();
  ASSERT("temp dir created", dir != NULL);

  domain_cfg = resp_array_init();
  int r = config_load(domain_cfg, dir);
  ASSERT("config_load returned 0 for empty dir", r == 0);

  resp_free(domain_cfg);
  domain_cfg = NULL;

  unlink(dir);
  free(dir);
}

int main(void) {
  RUN(test_config_load_single_file);
  RUN(test_config_load_directory);
  RUN(test_config_load_directory_recursive);
  RUN(test_config_load_directory_ignores_non_conf);
  RUN(test_config_load_directory_empty);
  return TEST_REPORT();
}
