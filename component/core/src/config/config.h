#ifndef UPBX_CONFIG_H
#define UPBX_CONFIG_H

#include <stddef.h>
#include <stdint.h>

struct upbx_listen_addr {
    char *url;
    char *scheme;
    char *host;
    char *port;
    char *path;
    int fd;
    struct upbx_listen_addr *next;
};

struct upbx_peer_config {
    char *url;
    char *scheme;
    char *name;
    char *host;
    char *port;
    char *path;
    char *address;
    char *username;
    char *password;
    struct upbx_peer_config *next;
};

struct upbx_user_config {
    char *username;
    char *secret;
    char *pubkey_hex;
    struct upbx_user_config *next;
};

struct upbx_config {
    struct upbx_listen_addr  *listen_addrs;
    struct upbx_peer_config   *peers;
    struct upbx_user_config  *users;
    char *cluster_secret;
    uint8_t cluster_pubkey[32];
    uint8_t cluster_privkey[64];
    int has_cluster_key;
};

struct upbx_config *upbx_config_load(const char *path);
void upbx_config_free(struct upbx_config *cfg);
struct upbx_user_config *upbx_config_find_user(struct upbx_config *cfg, const char *username);

#endif
