#ifndef TRK_CONFIG_H
#define TRK_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <regex.h>
#include <sys/socket.h>
#include <time.h>

struct trk_backbone {
    char *url;
    char *scheme;
    char *host;
    char *port;
    char *path;
    char *address;
    char *username;
    char *password;
    struct trk_backbone *next;
};

struct trk_filter_tag {
    char *name;
    char *value;
    int is_glob;
    regex_t compiled;
};

struct trk_filter {
    struct trk_filter_tag *tags;
    int tag_count;
    struct trk_filter *next;
};

struct trk_config {
    int sip_port;
    int rtp_min, rtp_max;
    int delay_ms;
    struct trk_backbone *backbones;
    struct trk_backbone *target;
    struct trk_filter *filters;
};

struct trk_config *trk_config_load(const char *path);
void trk_config_free(struct trk_config *cfg);

#endif
