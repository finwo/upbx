#ifndef GW_CONFIG_H
#define GW_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <regex.h>
#include <sys/socket.h>
#include <time.h>

struct gw_ext {
    char *extension;
    char *secret;
    char *pbx_addr;                         // "host:port" from SIP request-uri
    struct sockaddr_storage remote_addr;    // UDP source of REGISTER
    char *contact;
    time_t expires;
    int registered;
    int sip_fd;                             // fd that received the REGISTER
    struct gw_ext *next;
};

struct gw_backbone {
    char *url;
    char *scheme;
    char *host;
    char *port;
    char *path;
    char *address;                          // "host:port"
    char *username;
    char *password;
    struct gw_backbone *next;
};

struct gw_rewrite_rule {
    char *desc;
    char *pattern_str;
    char *replace_str;
    regex_t compiled;
    struct gw_rewrite_rule *next;
};

struct gw_did {
    char *did;
    struct gw_did *next;
};

struct gw_config {
    int sip_port;                           // default 5060
    int rtp_min, rtp_max;                   // default 10000, 20000
    char *cid;
    struct gw_did *dids;
    struct gw_backbone *backbones;
    struct gw_ext *extensions;
    struct gw_rewrite_rule *rewrite_rules;
};

struct gw_config *gw_config_load(const char *path);
void gw_config_free(struct gw_config *cfg);
struct gw_ext *gw_config_find_ext(struct gw_config *cfg, const char *ext);

#endif
