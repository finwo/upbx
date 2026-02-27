#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rxi/log.h"
#include "config.h"
#include "RespModule/resp.h"
#include "AppModule/pbx/registration.h"
#include "PluginModule/plugin.h"

#define MAX_EXTENSIONS 256

static extension_reg_t *extensions[MAX_EXTENSIONS];
static size_t extension_count = 0;

static extension_reg_t *find_by_number(const char *number) {
  for (size_t i = 0; i < extension_count; i++) {
    if (extensions[i] && strcmp(extensions[i]->number, number) == 0) {
      return extensions[i];
    }
  }
  return NULL;
}

extension_reg_t *registration_find(const char *number) {
  return find_by_number(number);
}

void registration_add(const char *number, const char *contact, const char *via_addr, int via_port, time_t expires) {
  extension_reg_t *ext = find_by_number(number);
  
  if (ext) {
    free(ext->contact);
    free(ext->via_addr);
  } else {
    if (extension_count >= MAX_EXTENSIONS) {
      log_error("registration: max extensions reached");
      return;
    }
    ext = calloc(1, sizeof(*ext));
    if (!ext) return;
    ext->number = strdup(number);
    extensions[extension_count++] = ext;
  }
  
  ext->contact = strdup(contact);
  free(ext->via_addr);
  ext->via_addr = strdup(via_addr);
  ext->via_port = via_port;
  ext->expires = expires;
  ext->registered_at = time(NULL);
  
  log_debug("registration: %s registered at %s:%d, expires %ld", 
            number, via_addr, via_port, (long)expires);
  
  registration_notify_plugins();
}

void registration_remove(const char *number) {
  extension_reg_t *ext = find_by_number(number);
  if (!ext) return;
  
  free(ext->number);
  free(ext->name);
  free(ext->contact);
  free(ext->via_addr);
  free(ext->realm);
  free(ext->nonce);
  
  for (size_t i = 0; i < extension_count; i++) {
    if (extensions[i] == ext) {
      memmove(&extensions[i], &extensions[i+1], (extension_count - i - 1) * sizeof(extension_reg_t*));
      extension_count--;
      break;
    }
  }
  free(ext);
  
  log_debug("registration: %s unregistered", number);
  registration_notify_plugins();
}

void registration_cleanup(void) {
  time_t now = time(NULL);
  for (size_t i = extension_count; i > 0; i--) {
    size_t idx = i - 1;
    extension_reg_t *ext = extensions[idx];
    if (ext && ext->expires > 0 && ext->expires < now) {
      log_info("registration: %s expired", ext->number);
      registration_remove(ext->number);
    }
  }
}

const char *registration_get_contact(const char *number) {
  extension_reg_t *ext = find_by_number(number);
  return ext ? ext->contact : NULL;
}

const char *registration_get_advertise_addr(const char *number, char *buf, size_t buf_len) {
  extension_reg_t *ext = find_by_number(number);
  if (!ext || !ext->via_addr) return NULL;
  
  snprintf(buf, buf_len, "%s:%d", ext->via_addr, ext->via_port);
  return buf;
}

void registration_notify_plugins(void) {
  if (!global_cfg) return;
  
  resp_object *list = resp_array_init();
  
  for (size_t i = 0; i < extension_count; i++) {
    extension_reg_t *ext = extensions[i];
    resp_object *ext_obj = resp_array_init();
    resp_array_append_bulk(ext_obj, "number");
    resp_array_append_bulk(ext_obj, ext->number ? ext->number : "");
    if (ext->name) {
      resp_array_append_bulk(ext_obj, "name");
      resp_array_append_bulk(ext_obj, ext->name);
    }
    resp_array_append_obj(list, ext_obj);
  }
  
  resp_object *argv[] = { list };
  plugmod_notify_event("extension.list", 1, (const resp_object *const *)&argv);
  resp_free(list);
}

size_t registration_get_regs(const char *trunk_name, const char *ext_number, extension_reg_t ***out) {
  size_t count = 0;
  extension_reg_t **result = NULL;
  
  for (size_t i = 0; i < extension_count; i++) {
    extension_reg_t *ext = extensions[i];
    if (ext->expires > 0 && ext->expires < time(NULL)) continue;
    
    if (trunk_name && (!ext->trunk_name || strcmp(ext->trunk_name, trunk_name) != 0)) continue;
    if (ext_number && (!ext->number || strcmp(ext->number, ext_number) != 0)) continue;
    
    extension_reg_t **r = realloc(result, (count + 1) * sizeof(extension_reg_t*));
    if (!r) { free(result); return 0; }
    result = r;
    result[count++] = ext;
  }
  
  *out = result;
  return count;
}