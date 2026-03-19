#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "auth/auth.h"
#include "util/hex.h"
#include "finwo/pbkdf2.h"
#include "orlp/ed25519.h"

#define PBKDF2_ITERATIONS 10000

int upbx_auth_check_nonce(const char *nonce_str) {
    if (!nonce_str) return -1;
    long nonce;
    if (sscanf(nonce_str, "%ld", &nonce) != 1) return -1;
    time_t now = time(NULL);
    if (nonce < now - 10 || nonce > now + 10) return -1;
    return 0;
}


void upbx_key_derive_user(const char *secret, const char *username, uint8_t *private_key_out) {
    pbkdf2((uint8_t *)secret, strlen(secret),
           (uint8_t *)username, strlen(username),
           PBKDF2_ITERATIONS, PBKDF2_SHA256,
           private_key_out, 32);
}

void upbx_key_derive_cluster(const char *cluster_secret, uint8_t *private_key_out) {
    pbkdf2((uint8_t *)cluster_secret, strlen(cluster_secret),
           (uint8_t *)"cluster", 7,
           PBKDF2_ITERATIONS, PBKDF2_SHA256,
           private_key_out, 32);
}

int upbx_auth_verify_user(const uint8_t *public_key, const char *username, const char *nonce, const char *signature_hex) {
    if (!public_key || !username || !nonce || !signature_hex) return -1;
    if (upbx_auth_check_nonce(nonce) != 0) return -1;

    uint8_t signature[64];
    if (hex_decode(signature_hex, signature, 64) != 64) return -1;

    size_t msg_len = strlen(username) + 1 + strlen(nonce);
    char *msg = malloc(msg_len + 1);
    snprintf(msg, msg_len + 1, "%s:%s", username, nonce);

    int result = ed25519_verify(signature, (uint8_t *)msg, msg_len, public_key);
    free(msg);
    return result == 1 ? 0 : -1;
}

int upbx_auth_sign_cluster(const uint8_t *pubkey, const uint8_t *privkey, char *out, size_t out_size) {
    if (!pubkey || !privkey || !out || out_size < 256) return -1;

    time_t nonce = time(NULL);
    char msg[64];
    snprintf(msg, sizeof(msg), ":%ld", (long)nonce);

    uint8_t sig[64];
    ed25519_sign(sig, (uint8_t *)msg, strlen(msg), pubkey, privkey);

    char sig_hex[129];
    hex_encode(sig, 64, sig_hex, sizeof(sig_hex));

    snprintf(out, out_size, "auth :%ld %s", (long)nonce, sig_hex);
    return 0;
}

int upbx_auth_verify_cluster(const uint8_t *cluster_pubkey, const char *nonce, const char *signature_hex) {
    if (!cluster_pubkey || !nonce || !signature_hex) return -1;
    if (upbx_auth_check_nonce(nonce) != 0) return -1;

    uint8_t signature[64];
    if (hex_decode(signature_hex, signature, 64) != 64) return -1;

    size_t msg_len = 1 + strlen(nonce);
    char *msg = malloc(msg_len + 1);
    snprintf(msg, msg_len + 1, ":%s", nonce);

    int result = ed25519_verify(signature, (uint8_t *)msg, msg_len, cluster_pubkey);
    free(msg);
    return result == 1 ? 0 : -1;
}
