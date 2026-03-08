#include "domain/pbx/registration.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/md5.h"
#include "common/resp.h"
#include "common/socket_util.h"
#include "domain/config.h"
#include "domain/pbx/extension.h"
#include "rxi/log.h"

static char data_dir[512] = "/var/lib/upbx";
static char addrmap_dir[512] = "";

static void _pbx_registration_addr_to_md5(const struct sockaddr *remote_addr, char *md5_out, size_t md5_out_size);
void _pbx_registration_write_addr_map(const struct sockaddr *remote_addr, const char *extension);
void _pbx_registration_remove_addr_map(const struct sockaddr *remote_addr);

static const char *pbx_config_get_data_dir(void) {
  if (!domain_cfg) return data_dir;
  resp_object *upbx_sec = resp_map_get(domain_cfg, "upbx");
  if (!upbx_sec) return data_dir;
  const char *val = resp_map_get_string(upbx_sec, "data_dir");
  return val ? val : data_dir;
}

static char *registration_filepath(const char *extension) {
  static char path[512];
  snprintf(path, sizeof(path), "%s/registrations/%s.resp", pbx_config_get_data_dir(), extension);
  return path;
}

void pbx_registration_init(void) {
  const char *dir = pbx_config_get_data_dir();
  snprintf(data_dir, sizeof(data_dir), "%s", dir);

  char regdir[512];
  snprintf(regdir, sizeof(regdir), "%s/registrations", data_dir);
  mkdir(regdir, 0755);

  snprintf(addrmap_dir, sizeof(addrmap_dir), "%s/addrmap", data_dir);
  mkdir(addrmap_dir, 0755);

  log_info("pbx: registrations dir: %s", regdir);
  log_info("pbx: addrmap dir: %s", addrmap_dir);
}

void pbx_registration_shutdown(void) {
}

pbx_registration_t *pbx_registration_find(const char *extension) {
  char *path = registration_filepath(extension);
  FILE *fp = fopen(path, "r");
  if (!fp) return NULL;

  char buf[1024];
  size_t total = 0;
  while (fgets(buf, sizeof(buf), fp)) {
    total += strlen(buf);
  }
  rewind(fp);

  char *data = malloc(total + 1);
  data[0] = '\0';
  while (fgets(buf, sizeof(buf), fp)) {
    strcat(data, buf);
  }
  fclose(fp);

  resp_object *obj = NULL;
  int r = resp_read_buf(data, total, &obj);
  free(data);

  if (r <= 0 || !obj) return NULL;

  pbx_registration_t *reg = calloc(1, sizeof(pbx_registration_t));
  strncpy(reg->extension, extension, sizeof(reg->extension) - 1);

  const char *val;
  val = resp_map_get_string(obj, "group_prefix");
  if (val) strncpy(reg->group_prefix, val, sizeof(reg->group_prefix) - 1);

  val = resp_map_get_string(obj, "contact");
  if (val) strncpy(reg->contact, val, sizeof(reg->contact) - 1);

  val = resp_map_get_string(obj, "expires");
  if (val) reg->expires = atoll(val);

  val = resp_map_get_string(obj, "remote_addr");
  if (val) {
    struct sockaddr_storage ss;
    if (string_to_sockaddr(val, &ss) == 0) {
      memcpy(&reg->remote_addr, &ss, sizeof(ss));
    }
  }

  val = resp_map_get_string(obj, "pbx_addr");
  if (val) strncpy(reg->pbx_addr, val, sizeof(reg->pbx_addr) - 1);

  resp_free(obj);

  if (reg->expires <= 0) {
    free(reg);
    return NULL;
  }

  return reg;
}

pbx_registration_t *pbx_registration_create(const char *extension, const char *contact, int fd, const struct sockaddr *remote_addr, int expires, const char *pbx_addr) {
  (void)fd;

  pbx_extension_t *ext = pbx_extension_find(extension);

  char *path = registration_filepath(extension);
  char dirpath[512];
  snprintf(dirpath, sizeof(dirpath), "%s/registrations", pbx_config_get_data_dir());
  mkdir(dirpath, 0755);

  resp_object *obj = resp_array_init();
  resp_map_set(obj, "extension", resp_simple_init(extension));
  
  if (ext && ext->group_prefix) {
    resp_map_set(obj, "group_prefix", resp_simple_init(ext->group_prefix));
  }
  resp_map_set(obj, "contact", resp_simple_init(contact ? contact : ""));

  char exp_str[32];
  int64_t exp_time = expires > 0 ? (time(NULL) + expires) : 0;
  snprintf(exp_str, sizeof(exp_str), "%lld", (long long)exp_time);
  resp_map_set(obj, "expires", resp_simple_init(exp_str));

  char addr_str[128] = "";
  if (remote_addr) {
    sockaddr_to_string(remote_addr, addr_str, sizeof(addr_str));
  }
  resp_map_set(obj, "remote_addr", resp_simple_init(addr_str));

  resp_map_set(obj, "pbx_addr", resp_simple_init(pbx_addr ? pbx_addr : ""));

  char *out_buf = NULL;
  size_t out_len = 0;
  resp_serialize(obj, &out_buf, &out_len);

  FILE *fp = fopen(path, "w");
  if (!fp) {
    log_error("pbx: failed to open %s for writing", path);
    free(out_buf);
    resp_free(obj);
    return NULL;
  }

  fwrite(out_buf, 1, out_len, fp);
  fclose(fp);
  free(out_buf);
  resp_free(obj);

  if (remote_addr) {
    _pbx_registration_write_addr_map(remote_addr, extension);
  }

  log_info("pbx: registered extension %s expires=%d", extension, expires);

  return pbx_registration_find(extension);
}

void pbx_registration_delete(const char *extension) {
  pbx_registration_t *reg = pbx_registration_find(extension);
  if (reg) {
    _pbx_registration_remove_addr_map((struct sockaddr *)&reg->remote_addr);
    free(reg);
  }

  char *path = registration_filepath(extension);
  unlink(path);
  log_info("pbx: unregistered extension %s", extension);
}

static void _pbx_registration_addr_to_md5(const struct sockaddr *remote_addr, char *md5_out, size_t md5_out_size) {
  char addr_str[128] = "";
  sockaddr_to_string(remote_addr, addr_str, sizeof(addr_str));

  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, addr_str, strlen(addr_str));
  unsigned char digest[16];
  MD5_Final(digest, &ctx);

  for (int i = 0; i < 16 && (size_t)(i * 2) < md5_out_size - 1; i++) {
    sprintf(md5_out + i * 2, "%02x", digest[i]);
  }
}

void _pbx_registration_write_addr_map(const struct sockaddr *remote_addr, const char *extension) {
  char md5hash[33] = "";
  _pbx_registration_addr_to_md5(remote_addr, md5hash, sizeof(md5hash));

  char path[512];
  snprintf(path, sizeof(path), "%s/%s", addrmap_dir, md5hash);

  FILE *fp = fopen(path, "w");
  if (fp) {
    fprintf(fp, "%s", extension);
    fclose(fp);
    log_debug("pbx: wrote addrmap %s -> %s", md5hash, extension);
  } else {
    log_error("pbx: failed to write addrmap %s", path);
  }
}

void _pbx_registration_remove_addr_map(const struct sockaddr *remote_addr) {
  char md5hash[33] = "";
  _pbx_registration_addr_to_md5(remote_addr, md5hash, sizeof(md5hash));

  char path[512];
  snprintf(path, sizeof(path), "%s/%s", addrmap_dir, md5hash);

  if (unlink(path) == 0) {
    log_debug("pbx: removed addrmap %s", md5hash);
  }
}

pbx_registration_t *pbx_registration_find_by_remote_addr(const struct sockaddr *remote_addr) {
  char md5hash[33] = "";
  _pbx_registration_addr_to_md5(remote_addr, md5hash, sizeof(md5hash));

  char path[512];
  snprintf(path, sizeof(path), "%s/%s", addrmap_dir, md5hash);

  FILE *fp = fopen(path, "r");
  if (!fp) {
    return NULL;
  }

  char ext[32] = "";
  if (fgets(ext, sizeof(ext), fp)) {
    size_t len = strlen(ext);
    if (len > 0 && ext[len - 1] == '\n') ext[len - 1] = '\0';
    if (len > 0 && ext[len - 1] == '\r') ext[len - 1] = '\0';
  }
  fclose(fp);

  if (ext[0] == '\0') {
    return NULL;
  }

  return pbx_registration_find(ext);
}

int pbx_registration_update_pbx_addr(const char *extension, const char *pbx_addr) {
  if (!extension || !pbx_addr) return -1;

  pbx_registration_t *reg = pbx_registration_find(extension);
  if (!reg) return -1;

  if (strcmp(reg->pbx_addr, pbx_addr) == 0) {
    free(reg);
    return 0;
  }

  char *path = registration_filepath(extension);

  resp_object *obj = resp_array_init();
  resp_map_set(obj, "extension", resp_simple_init(reg->extension));

  if (reg->group_prefix[0]) {
    resp_map_set(obj, "group_prefix", resp_simple_init(reg->group_prefix));
  }
  if (reg->contact[0]) {
    resp_map_set(obj, "contact", resp_simple_init(reg->contact));
  }

  char exp_str[32];
  snprintf(exp_str, sizeof(exp_str), "%lld", (long long)reg->expires);
  resp_map_set(obj, "expires", resp_simple_init(exp_str));

  char addr_str[128] = "";
  sockaddr_to_string((struct sockaddr *)&reg->remote_addr, addr_str, sizeof(addr_str));
  resp_map_set(obj, "remote_addr", resp_simple_init(addr_str));

  resp_map_set(obj, "pbx_addr", resp_simple_init(pbx_addr));

  char *out_buf = NULL;
  size_t out_len = 0;
  resp_serialize(obj, &out_buf, &out_len);

  FILE *fp = fopen(path, "w");
  if (!fp) {
    log_error("pbx: failed to open %s for writing", path);
    free(out_buf);
    resp_free(obj);
    free(reg);
    return -1;
  }

  fwrite(out_buf, 1, out_len, fp);
  fclose(fp);
  free(out_buf);
  resp_free(obj);
  free(reg);

  log_debug("pbx: updated pbx_addr for %s to %s", extension, pbx_addr);
  return 0;
}

int pbx_registration_cleanup(void) {
  char regdir[512];
  snprintf(regdir, sizeof(regdir), "%s/registrations", data_dir);
  
  int cleaned = 0;
  int64_t now = time(NULL);

  DIR *dir = opendir(regdir);
  if (!dir) return 0;

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_REG) continue;
    size_t len = strlen(entry->d_name);
    if (len <= 5 || strcmp(entry->d_name + len - 5, ".resp") != 0) continue;

    char ext[32];
    snprintf(ext, sizeof(ext), "%.*s", (int)(len - 5), entry->d_name);

    pbx_registration_t *reg = pbx_registration_find(ext);
    if (reg && reg->expires > 0 && reg->expires < now) {
      pbx_registration_delete(ext);
      cleaned++;
    }
    free(reg);
  }
  closedir(dir);

  if (cleaned > 0) {
    log_info("pbx: cleaned up %d expired registrations", cleaned);
  }
  return cleaned;
}

const char *pbx_registration_get_addrmap_dir(void) {
  return addrmap_dir;
}
