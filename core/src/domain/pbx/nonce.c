#include "domain/pbx/nonce.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NONCE_WINDOW_SECONDS 10

static char *nonce_secret = NULL;

void nonce_set_secret(const char *secret) {
  if (nonce_secret) {
    free(nonce_secret);
  }
  nonce_secret = secret ? strdup(secret) : NULL;
}

const char *nonce_get_secret(void) {
  return nonce_secret;
}

void nonce_generate(const char *ext_number, char *out, size_t out_size) {
  (void)ext_number;
  if (!out || out_size == 0) return;

  time_t now = time(NULL);
  snprintf(out, out_size, "%ld", (long)now);
}

int nonce_validate(const char *nonce, const char *ext_number) {
  (void)ext_number;
  if (!nonce) return -1;

  size_t len = strlen(nonce);
  if (len == 0 || len > 20) return -1;

  for (size_t i = 0; i < len; i++) {
    if (!isdigit((unsigned char)nonce[i])) return -1;
  }

  time_t ts = 0;
  for (size_t i = 0; i < len; i++) {
    ts = ts * 10 + (nonce[i] - '0');
  }

  time_t now = time(NULL);
  if (ts > now + NONCE_WINDOW_SECONDS || ts < now - NONCE_WINDOW_SECONDS) {
    return -1;
  }

  return 0;
}
