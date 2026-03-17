#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/scheduler.h"
#include "common/socket_util.h"
#include "domain/pbx/registration.h"
#include "rxi/log.h"

typedef struct {
  int64_t last_cleanup;
} pbx_cleanup_udata_t;

int registration_cleanup_pt(int64_t timestamp, struct pt_task *task) {
  pbx_cleanup_udata_t *udata = (pbx_cleanup_udata_t *)task->udata;

  if (!udata) {
    udata       = calloc(1, sizeof(pbx_cleanup_udata_t));
    task->udata = udata;
  }

  if (timestamp - udata->last_cleanup > 60000) {
    pbx_registration_cleanup();
    udata->last_cleanup = timestamp;
  }

  return SCHED_RUNNING;
}

#include "domain/pbx/media_proxy.h"

typedef struct {
  int64_t last_keepalive;
} pbx_keepalive_udata_t;

int udphole_keepalive_pt(int64_t timestamp, struct pt_task *task) {
  pbx_keepalive_udata_t *udata = (pbx_keepalive_udata_t *)task->udata;

  if (!udata) {
    udata       = calloc(1, sizeof(pbx_keepalive_udata_t));
    task->udata = udata;
  }

  if (timestamp - udata->last_keepalive > 30000) {
    pbx_media_proxy_connect();
    udata->last_keepalive = timestamp;
  }

  return SCHED_RUNNING;
}

#include "common/md5.h"

typedef struct {
  int64_t last_check;
  char    last_checked[64];
} pbx_addrmap_cleanup_udata_t;

static void _pbx_cleanup_addr_to_md5(const struct sockaddr *remote_addr, char *md5_out, size_t md5_out_size) {
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

int addrmap_cleanup_pt(int64_t timestamp, struct pt_task *task) {
  pbx_addrmap_cleanup_udata_t *udata = (pbx_addrmap_cleanup_udata_t *)task->udata;

  if (!udata) {
    udata       = calloc(1, sizeof(pbx_addrmap_cleanup_udata_t));
    task->udata = udata;
  }

  if (timestamp - udata->last_check < 1000) {
    return SCHED_RUNNING;
  }

  const char *addrmap_dir = pbx_registration_get_addrmap_dir();
  DIR        *dir         = opendir(addrmap_dir);
  if (!dir) {
    udata->last_check = timestamp;
    return SCHED_RUNNING;
  }

  struct dirent *entry;
  char           found_name[64] = "";
  char           found_ext[32]  = "";

  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_REG) continue;

    if (udata->last_checked[0] != '\0' && strcmp(entry->d_name, udata->last_checked) <= 0) {
      continue;
    }

    if (found_name[0] == '\0' || strcmp(entry->d_name, found_name) < 0) {
      strncpy(found_name, entry->d_name, sizeof(found_name) - 1);
      found_name[sizeof(found_name) - 1] = '\0';

      char path[512];
      snprintf(path, sizeof(path), "%s/%s", addrmap_dir, entry->d_name);
      FILE *fp = fopen(path, "r");
      if (fp) {
        if (fgets(found_ext, sizeof(found_ext), fp)) {
          size_t len = strlen(found_ext);
          if (len > 0 && found_ext[len - 1] == '\n') found_ext[len - 1] = '\0';
          if (len > 0 && found_ext[len - 1] == '\r') found_ext[len - 1] = '\0';
        }
        fclose(fp);
      }
    }
  }
  closedir(dir);

  if (found_name[0] != '\0') {
    pbx_registration_t *reg           = pbx_registration_find(found_ext);
    int                 should_remove = 0;

    if (!reg) {
      should_remove = 1;
      log_debug("pbx: addrmap cleanup: registration %s not found", found_ext);
    } else {
      char expected_md5[33] = "";
      _pbx_cleanup_addr_to_md5((struct sockaddr *)&reg->remote_addr, expected_md5, sizeof(expected_md5));
      if (strcmp(found_name, expected_md5) != 0) {
        should_remove = 1;
        log_debug("pbx: addrmap cleanup: remote_addr mismatch for %s", found_ext);
      }
      free(reg);
    }

    if (should_remove) {
      char path[512];
      snprintf(path, sizeof(path), "%s/%s", addrmap_dir, found_name);
      unlink(path);
      log_debug("pbx: addrmap cleanup: removed %s", found_name);
    }

    strncpy(udata->last_checked, found_name, sizeof(udata->last_checked) - 1);
    udata->last_checked[sizeof(udata->last_checked) - 1] = '\0';
  } else {
    udata->last_checked[0] = '\0';
  }

  udata->last_check = timestamp;
  return SCHED_RUNNING;
}
