#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "user/user.h"
#include "finwo/pbkdf2.h"
#include "orlp/ed25519.h"
#include "rxi/log.h"

#define PBKDF2_ITERATIONS 10000

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t len = strlen(hex);
    if (len != out_len * 2) return -1;
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        if (sscanf(hex + i, "%02x", &byte) != 1) return -1;
        out[i / 2] = (uint8_t)byte;
    }
    return 0;
}

struct upbx_user_registry *upbx_user_registry_create(void) {
    return calloc(1, sizeof(struct upbx_user_registry));
}

void upbx_user_registry_free(struct upbx_user_registry *reg) {
    if (!reg) return;
    struct upbx_user *u = reg->users;
    while (u) {
        struct upbx_user *next = u->next;
        free(u->username);
        free(u);
        u = next;
    }
    free(reg);
}

void upbx_user_registry_add(struct upbx_user_registry *reg, const char *username, const char *secret, const char *pubkey_hex) {
    struct upbx_user *user = calloc(1, sizeof(struct upbx_user));
    user->username = strdup(username);

    if (pubkey_hex) {
        if (hex_to_bytes(pubkey_hex, user->public_key, 32) == 0) {
            user->has_pubkey = 1;
        } else {
            log_error("user: invalid pubkey for %s", username);
            free(user->username);
            free(user);
            return;
        }
    } else if (secret) {
        uint8_t seed[32];
        uint8_t private_key[64];
        pbkdf2((uint8_t *)secret, strlen(secret),
               (uint8_t *)username, strlen(username),
               PBKDF2_ITERATIONS, PBKDF2_SHA256,
               seed, 32);
        ed25519_create_keypair(user->public_key, private_key, seed);
        user->has_pubkey = 1;
    }

    user->next = reg->users;
    reg->users = user;
}

struct upbx_user *upbx_user_registry_find(struct upbx_user_registry *reg, const char *username) {
    for (struct upbx_user *u = reg->users; u; u = u->next) {
        if (strcmp(u->username, username) == 0) return u;
    }
    return NULL;
}
