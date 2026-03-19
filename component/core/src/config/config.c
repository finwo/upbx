#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config/config.h"
#include "benhoyt/inih.h"
#include "finwo/url-parser.h"
#include "auth/auth.h"
#include "orlp/ed25519.h"
#include "rxi/log.h"

static int config_handler(void *user, const char *section, const char *name, const char *value) {
    struct upbx_config *cfg = user;

    if (strcmp(section, "upbx") == 0) {
        if (strcmp(name, "cluster_secret") == 0) {
            cfg->cluster_secret = strdup(value);
        } else if (strcmp(name, "listen") == 0 || strncmp(name, "listen", 6) == 0) {
            struct upbx_listen_addr *addr = calloc(1, sizeof(struct upbx_listen_addr));
            addr->url = strdup(value);
            struct parsed_url *pu = parse_url(value);
            if (pu) {
                addr->scheme = pu->scheme ? strdup(pu->scheme) : NULL;
                addr->host = pu->host ? strdup(pu->host) : NULL;
                addr->port = pu->port ? strdup(pu->port) : NULL;
                addr->path = pu->path ? strdup(pu->path) : NULL;
                parsed_url_free(pu);
            }
            addr->next = cfg->listen_addrs;
            cfg->listen_addrs = addr;
        } else if (strcmp(name, "peer") == 0 || strncmp(name, "peer", 4) == 0) {
            struct upbx_peer_config *peer = calloc(1, sizeof(struct upbx_peer_config));
            peer->url = strdup(value);
            struct parsed_url *pu = parse_url(value);
            if (pu) {
                peer->scheme = pu->scheme ? strdup(pu->scheme) : NULL;
                peer->name = pu->host ? strdup(pu->host) : (pu->path ? strdup(pu->path) : strdup(value));
                peer->host = pu->host ? strdup(pu->host) : NULL;
                peer->port = pu->port ? strdup(pu->port) : NULL;
                peer->path = pu->path ? strdup(pu->path) : NULL;
                if (pu->port) {
                    size_t len = strlen(pu->host ? pu->host : "") + strlen(pu->port) + 2;
                    peer->address = malloc(len);
                    snprintf(peer->address, len, "%s:%s", pu->host ? pu->host : "", pu->port);
                } else {
                    peer->address = pu->host ? strdup(pu->host) : NULL;
                }
                peer->username = pu->username ? strdup(pu->username) : NULL;
                peer->password = pu->password ? strdup(pu->password) : NULL;
                parsed_url_free(pu);
            } else {
                peer->name = strdup(value);
                peer->address = strdup(value);
            }
            peer->next = cfg->peers;
            cfg->peers = peer;
        }
    } else if (strncmp(section, "user:", 5) == 0) {
        struct upbx_user_config *user_cfg = calloc(1, sizeof(struct upbx_user_config));
        user_cfg->username = strdup(section + 5);
        if (strcmp(name, "secret") == 0) {
            user_cfg->secret = strdup(value);
        } else if (strcmp(name, "pubkey") == 0) {
            user_cfg->pubkey_hex = strdup(value);
        }
        user_cfg->next = cfg->users;
        cfg->users = user_cfg;
    }
    return 1;
}

struct upbx_config *upbx_config_load(const char *path) {
    struct upbx_config *cfg = calloc(1, sizeof(struct upbx_config));
    if (!cfg) return NULL;

    int ret = ini_parse(path, config_handler, cfg);
    if (ret < 0) {
        log_error("config: failed to parse %s: %s", path, ret == -1 ? "file not found" : "error");
        upbx_config_free(cfg);
        return NULL;
    }
    if (cfg->cluster_secret) {
        uint8_t seed[32];
        upbx_key_derive_cluster(cfg->cluster_secret, seed);
        uint8_t cluster_pub[32];
        uint8_t cluster_priv[64];
        ed25519_create_keypair(cluster_pub, cluster_priv, seed);
        memcpy(cfg->cluster_pubkey, cluster_pub, 32);
        memcpy(cfg->cluster_privkey, cluster_priv, 64);
        cfg->has_cluster_key = 1;
    }
    return cfg;
}

void upbx_config_free(struct upbx_config *cfg) {
    if (!cfg) return;
    struct upbx_listen_addr *la = cfg->listen_addrs;
    while (la) {
        struct upbx_listen_addr *next = la->next;
        free(la->url); free(la->scheme); free(la->host); free(la->port); free(la->path);
        free(la);
        la = next;
    }
    struct upbx_peer_config *pc = cfg->peers;
    while (pc) {
        struct upbx_peer_config *next = pc->next;
        free(pc->url); free(pc->scheme); free(pc->name); free(pc->host); free(pc->port); free(pc->path); free(pc->address); free(pc->username); free(pc->password);
        free(pc);
        pc = next;
    }
    struct upbx_user_config *uc = cfg->users;
    while (uc) {
        struct upbx_user_config *next = uc->next;
        free(uc->username); free(uc->secret); free(uc->pubkey_hex);
        free(uc);
        uc = next;
    }
    free(cfg->cluster_secret);
    free(cfg);
}

struct upbx_user_config *upbx_config_find_user(struct upbx_config *cfg, const char *username) {
    for (struct upbx_user_config *u = cfg->users; u; u = u->next) {
        if (strcmp(u->username, username) == 0) return u;
    }
    return NULL;
}
