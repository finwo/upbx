#include "pbx/extension.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/digest_auth.h"

#define NONCE_WINDOW 10

static char *extract_auth_param(const char *auth_header, const char *param) {
  if (!auth_header || !param) return NULL;

  const char *p = strstr(auth_header, param);
  if (!p) return NULL;

  p += strlen(param);
  while (*p == ' ' || *p == '=') p++;

  const char *end = p;
  while (*end && *end != ',' && *end != '\r' && *end != '\n') end++;

  while (end > p && (*(end - 1) == ' ' || *(end - 1) == '\t')) end--;

  return strndup(p, end - p);
}

static int validate_nonce(const char *nonce) {
  if (!nonce) return 0;

  char *endptr = NULL;
  long nonce_time = strtol(nonce, &endptr, 10);
  if (*endptr != '\0' || endptr == nonce) return 0;

  time_t now = time(NULL);
  if (nonce_time < now - NONCE_WINDOW || nonce_time > now) return 0;

  return 1;
}

struct pbx_extension_registry *pbx_extension_create(struct upbx_config *config) {
  struct pbx_extension_registry *pbx = calloc(1, sizeof(*pbx));
  pbx->config = config;
  pbx->entries = NULL;
  return pbx;
}

void pbx_extension_destroy(struct pbx_extension_registry *pbx) {
  if (!pbx) return;

  struct pbx_extension_entry *e = pbx->entries;
  while (e) {
    struct pbx_extension_entry *next = e->next;
    free(e->contact);
    free(e->nonce);
    free(e);
    e = next;
  }

  free(pbx);
}

static struct pbx_extension_entry *find_entry(struct pbx_extension_registry *pbx, const struct sockaddr_storage *addr) {
  struct pbx_extension_entry *e = pbx->entries;
  while (e) {
    if (memcmp(&e->remote_addr, addr, sizeof(*addr)) == 0) {
      return e;
    }
    e = e->next;
  }
  return NULL;
}

static struct pbx_extension_entry *find_or_create_entry(struct pbx_extension_registry *pbx, const struct sockaddr_storage *addr) {
  struct pbx_extension_entry *e = find_entry(pbx, addr);
  if (e) return e;

  e = calloc(1, sizeof(*e));
  memcpy(&e->remote_addr, addr, sizeof(*addr));
  e->config = pbx->config;

  e->next = pbx->entries;
  pbx->entries = e;

  return e;
}

void pbx_extension_set_contact(struct pbx_extension_entry *ext, const char *contact, int64_t expires) {
  if (!ext) return;
  free(ext->contact);
  ext->contact = contact ? strdup(contact) : NULL;
  ext->expires = expires;
}

void pbx_extension_set_pbx_addr(struct pbx_extension_entry *ext, const char *pbx_addr) {
  if (!ext) return;
  free(ext->pbx_addr);
  ext->pbx_addr = pbx_addr ? strdup(pbx_addr) : NULL;
}

struct pbx_extension_entry *pbx_extension_find_by_addr(const struct pbx_extension_registry *pbx, const struct sockaddr_storage *addr) {
  if (!pbx || !addr) return NULL;

  const struct pbx_extension_entry *e = pbx->entries;
  while (e) {
    if (memcmp(&e->remote_addr, addr, sizeof(*addr)) == 0) {
      return (struct pbx_extension_entry *)e;
    }
    e = e->next;
  }
  return NULL;
}

static const char *get_ext_id_from_request_uri(const char *uri) {
  if (!uri) return NULL;

  const char *p = uri;
  while (*p && *p != ':') p++;
  if (*p == ':') p++;

  const char *end = p;
  while (*end && *end != '@' && *end != ';' && *end != ' ' && *end != '\r' && *end != '\n') end++;

  return strndup(p, end - p);
}

static void strip_quotes(char *s) {
  if (s && s[0] == '"') {
    memmove(s, s + 1, strlen(s));
    size_t len = strlen(s);
    if (len > 0 && s[len - 1] == '"') {
      s[len - 1] = '\0';
    }
  }
}

static int check_digest_auth(struct pbx_extension_entry *entry, const char *method, const char *uri, const char *auth_header) {
  if (!entry || !method || !uri || !auth_header) return 0;

  fprintf(stderr, "DEBUG check_digest_auth: entry=%p method=%s uri=%s\n", (void*)entry, method, uri);
  fprintf(stderr, "DEBUG check_digest_auth: auth_header=%.200s\n", auth_header);
  fflush(stderr);

  if (!entry->config_ext || !entry->config_ext->secret) return 0;

  char *username = extract_auth_param(auth_header, "username");
  char *realm = extract_auth_param(auth_header, "realm");
  char *nonce = extract_auth_param(auth_header, "nonce");
  char *uri_str = extract_auth_param(auth_header, "uri");
  char *response = extract_auth_param(auth_header, "response");

  strip_quotes(username);
  strip_quotes(realm);
  strip_quotes(nonce);
  strip_quotes(uri_str);
  strip_quotes(response);

  fprintf(stderr, "DEBUG: username=%s realm=%s nonce=%s uri_str=%s response=%s\n",
    username ? username : "null",
    realm ? realm : "null",
    nonce ? nonce : "null",
    uri_str ? uri_str : "null",
    response ? response : "null");
  fflush(stderr);

  if (!username || !nonce || !uri_str || !response) {
    free(username);
    free(realm);
    free(nonce);
    free(uri_str);
    free(response);
    return 0;
  }

  if (strcmp(username, entry->config_ext->id) != 0) {
    fprintf(stderr, "DEBUG: username mismatch: got %s, expected %s\n", username, entry->config_ext->id);
    fflush(stderr);
    free(username);
    free(realm);
    free(nonce);
    free(uri_str);
    free(response);
    return 0;
  }

  if (!validate_nonce(nonce)) {
    fprintf(stderr, "DEBUG: nonce validation failed: %s\n", nonce);
    fflush(stderr);
    free(username);
    free(realm);
    free(nonce);
    free(uri_str);
    free(response);
    return 0;
  }

  const char *realm_str = "upbx";
  if (realm && strcmp(realm, realm_str) != 0) {
    fprintf(stderr, "DEBUG: realm mismatch: got %s, expected %s\n", realm, realm_str);
    fflush(stderr);
    free(username);
    free(realm);
    free(nonce);
    free(uri_str);
    free(response);
    return 0;
  }

  HASHHEX ha1, ha2, expected_response;
  const char *auth_username = entry->config_ext->id;
  fprintf(stderr, "DEBUG: using username for ha1: %s\n", auth_username);
  fflush(stderr);
  digest_calc_ha1(auth_username, realm_str, entry->config_ext->secret, ha1);
  digest_calc_ha2(method, uri_str, ha2);
  digest_calc_response((const char *)ha1, nonce, (const char *)ha2, expected_response);

  fprintf(stderr, "DEBUG: ha1=%s ha2=%s expected_response=%s\n", ha1, ha2, expected_response);
  fprintf(stderr, "DEBUG: entry->nonce=%s\n", entry->nonce ? entry->nonce : "null");
  fflush(stderr);

  int valid = (strcmp(response, (const char *)expected_response) == 0);

  fprintf(stderr, "DEBUG: valid=%d response=%s\n", valid, response);
  fflush(stderr);

  free(username);
  free(realm);
  free(nonce);
  free(uri_str);
  free(response);

  return valid;
}

int pbx_extension_handle_register(struct pbx_extension_registry *pbx, struct upbx_extension *config_ext, const char *contact, int expires, const char *auth_header, const struct sockaddr_storage *src, const char *request_uri) {
  fprintf(stderr, "DEBUG pbx_extension_handle_register: pbx=%p config_ext=%p contact=%s expires=%d auth_header=%s\n",
    (void*)pbx, (void*)config_ext, contact ? contact : "null", expires, auth_header ? auth_header : "null");
  fflush(stderr);

  if (!pbx || !config_ext) return -1;

  if (expires > 300) expires = 300;
  if (expires <= 0) expires = 60;

  struct pbx_extension_entry *entry = find_or_create_entry(pbx, src);
  entry->config_ext = config_ext;

  snprintf(entry->id, sizeof(entry->id), "%s", config_ext->id);

  fprintf(stderr, "DEBUG: entry->id=%s entry->config_ext->id=%s\n", entry->id, config_ext->id);
  fflush(stderr);

  if (request_uri) {
    const char *ext_id = get_ext_id_from_request_uri(request_uri);
    if (ext_id) {
      fprintf(stderr, "DEBUG: set pbx_addr from request_uri: %s\n", ext_id);
      fflush(stderr);
      pbx_extension_set_pbx_addr(entry, ext_id);
      free((char *)ext_id);
    }
  }

  if (!auth_header || (auth_header && strlen(auth_header) == 0)) {
    fprintf(stderr, "DEBUG: no auth_header, generating nonce\n");
    fflush(stderr);
    time_t now = time(NULL);
    free(entry->nonce);
    entry->nonce = malloc(32);
    snprintf(entry->nonce, 32, "%ld", (long)now);
    entry->nonce_time = now;
    return 401;
  }

  const char *auth_uri = request_uri ? request_uri : "sip:upbx";
  fprintf(stderr, "DEBUG: calling check_digest_auth with auth_uri=%s\n", auth_uri);
  fflush(stderr);
  if (!check_digest_auth(entry, "REGISTER", auth_uri, auth_header)) {
    fprintf(stderr, "DEBUG: check_digest_auth FAILED, returning 403\n");
    fflush(stderr);
    return 403;
  }

  fprintf(stderr, "DEBUG: auth succeeded, setting contact\n");
  fflush(stderr);
  pbx_extension_set_contact(entry, contact, time(NULL) + expires);

  return 200;
}

char *pbx_extension_get_nonce(struct pbx_extension_registry *pbx, const struct sockaddr_storage *src) {
  if (!pbx || !src) return NULL;

  struct pbx_extension_entry *e = pbx->entries;
  while (e) {
    if (memcmp(&e->remote_addr, src, sizeof(*src)) == 0) {
      return e->nonce;
    }
    e = e->next;
  }
  return NULL;
}

void pbx_extension_cleanup_expired(struct pbx_extension_registry *pbx) {
  if (!pbx) return;

  time_t now = time(NULL);

  struct pbx_extension_entry **prev = &pbx->entries;
  struct pbx_extension_entry *e = pbx->entries;

  while (e) {
    if (e->expires > 0 && e->expires < now) {
      *prev = e->next;
      free(e->contact);
      free(e->nonce);
      free(e);
      e = *prev;
    } else {
      prev = &e->next;
      e = e->next;
    }
  }
}
