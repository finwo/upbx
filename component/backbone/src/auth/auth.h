#ifndef UPBX_AUTH_H
#define UPBX_AUTH_H

#include <stddef.h>
#include <stdint.h>

int upbx_auth_verify_user(
    const uint8_t *public_key,
    const char *username,
    const char *nonce,
    const char *signature_hex
);

int upbx_auth_verify_cluster(
    const uint8_t *cluster_pubkey,
    const char *nonce,
    const char *signature_hex
);

int upbx_auth_check_nonce(const char *nonce_str);

void upbx_key_derive_user(const char *secret, const char *username, uint8_t *private_key_out);
void upbx_key_derive_cluster(const char *cluster_secret, uint8_t *private_key_out);

int upbx_auth_sign_cluster(const uint8_t *pubkey, const uint8_t *privkey, char *out, size_t out_size);

#endif
