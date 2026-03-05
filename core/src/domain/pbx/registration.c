#include "domain/pbx/registration.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/resp.h"
#include "common/socket_util.h"
#include "rxi/log.h"

#define MAX_REGISTRATIONS    1024
#define CLEANUP_INTERVAL_SEC 60

static registration_t *registrations[MAX_REGISTRATIONS];
static size_t          registration_count = 0;
static char           *registrations_dir  = NULL;

void registration_set_dir(const char *path) {
  if (registrations_dir) free(registrations_dir);
  registrations_dir = path ? strdup(path) : NULL;
}

const char *registration_get_dir(void) {
  return registrations_dir;
}

static int save_registration_to_file(const registration_t *reg) {
  if (!reg || !reg->number || !registrations_dir) return -1;

  if (mkdir(registrations_dir, 0755) != 0 && errno != EEXIST) {
    log_error("registration: failed to create directory %s: %s", registrations_dir, strerror(errno));
    return -1;
  }

  char path[512];
  snprintf(path, sizeof(path), "%s/%s.reg", registrations_dir, reg->number);

  char addr_str[INET6_ADDRSTRLEN + 8] = "";
  sockaddr_to_string((const struct sockaddr *)&reg->remote_addr, addr_str, sizeof(addr_str));

  resp_object *obj = resp_array_init();
  if (!obj) return -1;

  resp_array_append_bulk(obj, "number");
  resp_array_append_bulk(obj, reg->number);
  resp_array_append_bulk(obj, "contact");
  resp_array_append_bulk(obj, reg->contact ? reg->contact : "");
  resp_array_append_bulk(obj, "group");
  resp_array_append_bulk(obj, reg->group ? reg->group : "");
  resp_array_append_bulk(obj, "remote_addr");
  resp_array_append_bulk(obj, addr_str);
  resp_array_append_bulk(obj, "expires_at");
  resp_array_append_int(obj, (long long)reg->expires_at);
  resp_array_append_bulk(obj, "registered_at");
  resp_array_append_int(obj, (long long)reg->registered_at);

  char                    *buf     = NULL;
  size_t                   buf_len = 0;
  const resp_object *const argv[]  = {obj};
  if (resp_encode_array(1, argv, &buf, &buf_len) != 0) {
    resp_free(obj);
    return -1;
  }

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    log_error("registration: failed to open %s: %s", path, strerror(errno));
    free(buf);
    resp_free(obj);
    return -1;
  }

  ssize_t written = write(fd, buf, buf_len);
  close(fd);
  free(buf);
  resp_free(obj);

  if (written != (ssize_t)buf_len) {
    log_error("registration: failed to write %s", path);
    return -1;
  }

  return 0;
}

static int delete_registration_file(const char *number) {
  if (!number || !registrations_dir) return -1;

  char path[512];
  snprintf(path, sizeof(path), "%s/%s.reg", registrations_dir, number);

  if (unlink(path) != 0 && errno != ENOENT) {
    log_error("registration: failed to delete %s: %s", path, strerror(errno));
    return -1;
  }

  return 0;
}

static registration_t *load_registration_from_file(const char *number) {
  if (!number || !registrations_dir) return NULL;

  char path[512];
  snprintf(path, sizeof(path), "%s/%s.reg", registrations_dir, number);

  int fd = open(path, O_RDONLY);
  if (fd < 0) return NULL;

  resp_object *obj = resp_read(fd);
  close(fd);

  if (!obj || obj->type != RESPT_ARRAY) {
    if (obj) resp_free(obj);
    return NULL;
  }

  const char *num = resp_map_get_string(obj, "number");
  if (!num || strcmp(num, number) != 0) {
    resp_free(obj);
    return NULL;
  }

  registration_t *reg = calloc(1, sizeof(registration_t));
  if (!reg) {
    resp_free(obj);
    return NULL;
  }

  reg->number  = strdup(num);
  reg->contact = strdup(resp_map_get_string(obj, "contact") ? resp_map_get_string(obj, "contact") : "");

  const char *grp = resp_map_get_string(obj, "group");
  if (grp && grp[0]) {
    reg->group = strdup(grp);
  }

  const char *addr_str = resp_map_get_string(obj, "remote_addr");
  if (addr_str && addr_str[0]) {
    string_to_sockaddr(addr_str, &reg->remote_addr);
  }

  resp_object *val;
  val             = resp_map_get(obj, "expires_at");
  reg->expires_at = val && val->type == RESPT_INT ? (time_t)val->u.i : 0;

  val                = resp_map_get(obj, "registered_at");
  reg->registered_at = val && val->type == RESPT_INT ? (time_t)val->u.i : 0;

  resp_free(obj);
  return reg;
}

void registration_init(void) {
  if (!registrations_dir) {
    registrations_dir = strdup("/var/lib/upbx/registrations");
  }

  if (mkdir(registrations_dir, 0755) != 0 && errno != EEXIST) {
    log_warn("registration: could not create directory %s: %s", registrations_dir, strerror(errno));
    return;
  }

  log_info("registration: loading from %s", registrations_dir);
}

registration_t *registration_find(const char *number) {
  if (!number) return NULL;

  for (size_t i = 0; i < registration_count; i++) {
    if (registrations[i] && registrations[i]->number && strcmp(registrations[i]->number, number) == 0) {
      if (registrations[i]->expires_at > 0 && registrations[i]->expires_at < time(NULL)) {
        continue;
      }
      return registrations[i];
    }
  }

  registration_t *reg = load_registration_from_file(number);
  if (reg) {
    if (reg->expires_at > 0 && reg->expires_at < time(NULL)) {
      registration_free(reg);
      delete_registration_file(number);
      return NULL;
    }
    if (registration_count < MAX_REGISTRATIONS) {
      registrations[registration_count++] = reg;
      return reg;
    }
    registration_free(reg);
  }

  return NULL;
}

registration_t *registration_find_by_addr(const struct sockaddr *remote_addr) {
  if (!remote_addr) return NULL;

  for (size_t i = 0; i < registration_count; i++) {
    if (registrations[i] && sockaddr_equal(remote_addr, (const struct sockaddr *)&registrations[i]->remote_addr)) {
      if (registrations[i]->expires_at > 0 && registrations[i]->expires_at < time(NULL)) {
        continue;
      }
      return registrations[i];
    }
  }
  return NULL;
}

int registration_is_pattern(const char *extension) {
  if (!extension) return 0;
  const char *p = extension;
  while (*p) {
    if (*p == 'x' || *p == 'z' || *p == 'n' || *p == '.' || *p == '!') {
      return 1;
    }
    p++;
  }
  return 0;
}

static int token_specificity(char c) {
  switch (c) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return 5;
    case 'n':
      return 4;
    case 'z':
      return 3;
    case 'x':
      return 2;
    case '.':
      return 1;
    case '!':
      return 0;
    default:
      return -1;
  }
}

int registration_match_pattern(const char *pattern, const char *extension) {
  if (!pattern || !extension) return 0;

  size_t pat_len = strlen(pattern);
  size_t ext_len = strlen(extension);

  if (pat_len == 0) return 0;
  if (ext_len > 0 && extension[ext_len - 1] == '!') {
    ext_len--;
  }

  for (size_t i = 0; i < pat_len && i < ext_len; i++) {
    char pc = pattern[i];
    char ec = extension[i];

    if (pc == 'x') {
      if (ec < '0' || ec > '9') return 0;
    } else if (pc == 'z') {
      if (ec < '1' || ec > '9') return 0;
    } else if (pc == 'n') {
      if (ec < '2' || ec > '9') return 0;
    } else if (pc == '.') {
      return 1;
    } else if (pc == '!') {
      return 1;
    } else if (pc != ec) {
      return 0;
    }
  }

  if (pat_len == ext_len) return 1;
  if (pat_len > ext_len) {
    if (pat_len > 0 && pattern[pat_len - 1] == '!') return 1;
    return 0;
  }
  if (pat_len > 0 && pattern[pat_len - 1] == '.') return 1;
  if (pat_len > 0 && pattern[pat_len - 1] == '!') return 1;

  return 0;
}

int pattern_specificity_cmp(const char *a, const char *b) {
  size_t len_a = strlen(a);
  size_t len_b = strlen(b);
  size_t max_len = len_a > len_b ? len_a : len_b;

  for (size_t i = 0; i < max_len; i++) {
    char ca = i < len_a ? a[i] : '\0';
    char cb = i < len_b ? b[i] : '\0';

    if (ca == '\0' && cb == '\0') return 0;
    if (ca == '\0') return -1;
    if (cb == '\0') return 1;

    int sa = token_specificity(ca);
    int sb = token_specificity(cb);

    if (sa != sb) return sb - sa;
    if (ca != cb) return cb - ca;
  }

  return 0;
}

const char *registration_pattern_best_match(const char *extension) {
  if (!extension) return NULL;

  const char *best_pattern = NULL;

  for (size_t i = 0; i < registration_count; i++) {
    if (!registrations[i] || !registrations[i]->number) continue;
    if (!registration_is_pattern(registrations[i]->number)) continue;

    if (registration_match_pattern(registrations[i]->number, extension)) {
      if (!best_pattern || pattern_specificity_cmp(registrations[i]->number, best_pattern) > 0) {
        best_pattern = registrations[i]->number;
      }
    }
  }

  registration_t *reg = load_registration_from_file(extension);
  if (reg) {
    if (reg->number && registration_is_pattern(reg->number)) {
      if (registration_match_pattern(reg->number, extension)) {
        if (!best_pattern || pattern_specificity_cmp(reg->number, best_pattern) > 0) {
          best_pattern = reg->number;
        }
      }
    }
    registration_free(reg);
  }

  return best_pattern;
}

int registration_add(const char *number, const char *contact, const char *group, const struct sockaddr *remote_addr, int expires_seconds) {
  if (!number) return -1;

  registration_t *reg = registration_find(number);
  if (!reg) {
    if (registration_count >= MAX_REGISTRATIONS) {
      log_error("registration: max registrations reached");
      return -1;
    }
    reg = calloc(1, sizeof(registration_t));
    if (!reg) return -1;
    reg->number                         = strdup(number);
    registrations[registration_count++] = reg;
  }

  if (reg->contact) free(reg->contact);
  reg->contact = contact ? strdup(contact) : strdup("");

  if (reg->group) free(reg->group);
  reg->group = group ? strdup(group) : NULL;

  if (remote_addr) {
    memcpy(&reg->remote_addr, remote_addr, sizeof(reg->remote_addr));
  }

  time_t now         = time(NULL);
  reg->registered_at = now;
  reg->expires_at    = expires_seconds > 0 ? now + expires_seconds : 0;

  if (save_registration_to_file(reg) != 0) {
    log_error("registration: failed to save %s to file", number);
    if (reg->contact) {
      free(reg->contact);
      reg->contact = NULL;
    }
    if (reg->group) {
      free(reg->group);
      reg->group = NULL;
    }
    reg->expires_at    = 0;
    reg->registered_at = 0;
    return -1;
  }

  char addr_str[INET6_ADDRSTRLEN + 8] = "";
  if (remote_addr) {
    sockaddr_to_string(remote_addr, addr_str, sizeof(addr_str));
  }
  log_info("registration: %s registered from %s, expires in %d seconds", number, addr_str[0] ? addr_str : "unknown",
           expires_seconds);

  return 0;
}

void registration_remove(const char *number) {
  if (!number) return;

  for (size_t i = 0; i < registration_count; i++) {
    if (registrations[i] && registrations[i]->number && strcmp(registrations[i]->number, number) == 0) {
      log_info("registration: %s unregistered", number);

      registration_free(registrations[i]);

      for (size_t j = i; j < registration_count - 1; j++) {
        registrations[j] = registrations[j + 1];
      }
      registration_count--;
      registrations[registration_count] = NULL;

      delete_registration_file(number);
      return;
    }
  }
}

void registration_free(registration_t *reg) {
  if (!reg) return;
  free(reg->number);
  free(reg->contact);
  free(reg->group);
  free(reg);
}

typedef struct {
  int64_t last_cleanup;
} registration_cleanup_udata_t;

int registration_cleanup_pt(int64_t timestamp, struct pt_task *task) {
  registration_cleanup_udata_t *udata = task->udata;

  if (!udata) {
    udata = calloc(1, sizeof(registration_cleanup_udata_t));
    if (!udata) return SCHED_ERROR;
    udata->last_cleanup = timestamp;
    task->udata         = udata;
  }

  if (timestamp - udata->last_cleanup >= CLEANUP_INTERVAL_SEC * 1000) {
    udata->last_cleanup = timestamp;
    time_t now          = time(NULL);

    for (size_t i = registration_count; i > 0; i--) {
      size_t          idx = i - 1;
      registration_t *reg = registrations[idx];
      if (reg && reg->expires_at > 0 && reg->expires_at < now) {
        log_info("registration: %s expired", reg->number);
        char *number = strdup(reg->number);
        registration_remove(number);
        free(number);
      }
    }
  }

  return SCHED_RUNNING;
}
