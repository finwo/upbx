#ifndef UPBX_USER_H
#define UPBX_USER_H

#include <stddef.h>
#include <stdint.h>

struct upbx_user {
    char *username;
    uint8_t public_key[32];
    int has_pubkey;
    struct upbx_user *next;
};

struct upbx_user_registry {
    struct upbx_user *users;
};

struct upbx_user_registry *upbx_user_registry_create(void);
void upbx_user_registry_free(struct upbx_user_registry *reg);
void upbx_user_registry_add(struct upbx_user_registry *reg, const char *username, const char *secret, const char *pubkey_hex);
struct upbx_user *upbx_user_registry_find(struct upbx_user_registry *reg, const char *username);

#endif
