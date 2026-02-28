#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "common/md5.h"
#include "common/util/hex.h"
#include "AppModule/pbx/nonce.h"

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
    if (!out || out_size == 0) return;

    time_t now = time(NULL);
    char to_hash[256];
    unsigned char hash[16];
    char hash_hex[33];

    snprintf(to_hash, sizeof(to_hash), "%ld:%s:%s",
             (long)now,
             ext_number ? ext_number : "",
             nonce_secret ? nonce_secret : "");

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, to_hash, strlen(to_hash));
    MD5_Final(hash, &ctx);

    hex_bytes_to_str(hash, 16, hash_hex);

    snprintf(out, out_size, "%ld:%s", (long)now, hash_hex);
}

int nonce_validate(const char *nonce, const char *ext_number) {
    if (!nonce || !ext_number) return -1;

    const char *colon = strchr(nonce, ':');
    if (!colon) return -1;

    size_t ts_len = (size_t)(colon - nonce);
    if (ts_len == 0 || ts_len > 20) return -1;

    char ts_str[32];
    memcpy(ts_str, nonce, ts_len);
    ts_str[ts_len] = '\0';

    time_t ts = 0;
    for (size_t i = 0; i < ts_len; i++) {
        if (!isdigit((unsigned char)ts_str[i])) return -1;
        ts = ts * 10 + (ts_str[i] - '0');
    }

    time_t now = time(NULL);
    if (ts > now + NONCE_WINDOW_SECONDS || ts < now - NONCE_WINDOW_SECONDS) {
        return -1;
    }

    const char *hash_hex = colon + 1;
    size_t hash_len = strlen(hash_hex);
    if (hash_len != 32) return -1;

    char expected[64];
    nonce_generate(ext_number, expected, sizeof(expected));

    const char *expected_hash = strchr(expected, ':');
    if (!expected_hash) return -1;
    expected_hash++;

    if (strcmp(hash_hex, expected_hash) != 0) {
        return -1;
    }

    return 0;
}
