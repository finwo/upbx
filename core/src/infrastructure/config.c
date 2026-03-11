#include "infrastructure/config.h"

#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "benhoyt/inih.h"
#include "common/resp.h"
#include "domain/config.h"
#include "rxi/log.h"

resp_object *pending_cfg = NULL;

static const char *stored_config_path = NULL;

static int config_handler(void *user, const char *section, const char *name, const char *value, int lineno);

static int config_compare_strings(const void *a, const void *b) {
  const char **sa = (const char **)a;
  const char **sb = (const char **)b;
  return strcmp(*sa, *sb);
}

static int config_load_directory(resp_object *cfg, const char *dirpath) {
  char **files    = NULL;
  size_t file_count = 0;
  size_t file_capacity = 0;

  DIR *dir = opendir(dirpath);
  if (!dir) {
    log_error("config: failed to open directory '%s'", dirpath);
    return -1;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type == DT_DIR) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }
      char subpath[PATH_MAX];
      snprintf(subpath, sizeof(subpath), "%s/%s", dirpath, entry->d_name);
      config_load_directory(cfg, subpath);
    } else if (entry->d_type == DT_REG) {
      size_t len = strlen(entry->d_name);
      if (len > 5 && strcmp(entry->d_name + len - 5, ".conf") == 0) {
        if (file_count >= file_capacity) {
          file_capacity = file_capacity == 0 ? 16 : file_capacity * 2;
          files = realloc(files, file_capacity * sizeof(char *));
        }
        char *filepath = malloc(PATH_MAX);
        snprintf(filepath, PATH_MAX, "%s/%s", dirpath, entry->d_name);
        files[file_count++] = filepath;
      }
    }
  }
  closedir(dir);

  if (file_count > 0) {
    qsort(files, file_count, sizeof(char *), config_compare_strings);
    for (size_t i = 0; i < file_count; i++) {
      log_info("config: loading '%s'", files[i]);
      int r = ini_parse(files[i], config_handler, cfg);
      if (r < 0) {
        log_error("config: failed to parse '%s'", files[i]);
      } else if (r > 0) {
        log_error("config: error at line %d in '%s'", r, files[i]);
      }
      free(files[i]);
    }
    free(files);
  }

  return 0;
}

static int config_handler(void *user, const char *section, const char *name, const char *value, int lineno) {
  (void)lineno;
  resp_object *cfg = (resp_object *)user;
  resp_object *sec = resp_map_get(cfg, section);
  if (!sec || sec->type != RESPT_ARRAY) {
    sec = resp_array_init();
    resp_map_set(cfg, section, sec);
    sec = resp_map_get(cfg, section);
  }

  if (strcmp(name, "listen") == 0 ||
      strcmp(name, "address") == 0 ||
      strcmp(name, "rtpproxy") == 0 ||
      strcmp(name, "did") == 0 ||
      strcmp(name, "group") == 0) {
    resp_object *arr = resp_map_get(sec, name);
    if (!arr) {
      arr = resp_array_init();
      resp_map_set(sec, name, arr);
      arr = resp_map_get(sec, name);
    }
    if (!arr || arr->type != RESPT_ARRAY) {
      log_error("config: '%s' key already exists as non-array", name);
      return 0;
    }
    resp_array_append_bulk(arr, value);
  } else {
    resp_array_append_bulk(sec, name);
    resp_array_append_bulk(sec, value);
  }
  return 1;
}

void config_init(void) {
  if (pending_cfg) resp_free(pending_cfg);
  pending_cfg = resp_array_init();
  config_load(NULL, config_get_path());
  resp_object *old = domain_cfg;
  domain_cfg       = pending_cfg;
  pending_cfg      = NULL;
  if (old) resp_free(old);
}

int config_load(resp_object *cfg, const char *path) {
  resp_object *load_cfg = cfg;
  if (!load_cfg) {
    load_cfg = pending_cfg;
  }

  struct stat st;
  if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
    return config_load_directory(load_cfg, path);
  }

  return ini_parse(path, config_handler, load_cfg);
}

void config_pending_init(void) {
  if (pending_cfg) resp_free(pending_cfg);
  pending_cfg = resp_array_init();
}

int config_reload(void) {
  config_pending_init();
  int r = config_load(NULL, config_get_path());
  if (r < 0) return -1;
  resp_object *old = domain_cfg;
  domain_cfg       = pending_cfg;
  pending_cfg      = NULL;
  if (old) resp_free(old);
  return 0;
}

void config_set_path(const char *path) {
  if (stored_config_path) free((void *)stored_config_path);
  stored_config_path = path ? strdup(path) : NULL;
}

const char *config_get_path(void) {
  return stored_config_path;
}
