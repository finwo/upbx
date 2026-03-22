#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config/config.h"
#include "benhoyt/inih.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

static int is_numbered(const char *name, const char *prefix) {
    size_t plen = strlen(prefix);
    if (strncmp(name, prefix, plen) != 0) return 0;
    if (name[plen] == '\0') return 1;
    const char *p = name + plen;
    while (*p) {
        if (*p < '0' || *p > '9') return 0;
        p++;
    }
    return 1;
}

static struct trk_backbone *parse_backbone_url(const char *value) {
    struct trk_backbone *bb = calloc(1, sizeof(struct trk_backbone));
    bb->url = strdup(value);
    struct parsed_url *pu = parse_url(value);
    if (pu) {
        bb->scheme = pu->scheme ? strdup(pu->scheme) : NULL;
        bb->host = pu->host ? strdup(pu->host) : NULL;
        bb->port = pu->port ? strdup(pu->port) : NULL;
        bb->path = pu->path ? strdup(pu->path) : NULL;
        bb->username = pu->username ? strdup(pu->username) : NULL;
        bb->password = pu->password ? strdup(pu->password) : NULL;
        if (pu->host && pu->port) {
            size_t len = strlen(pu->host) + strlen(pu->port) + 2;
            bb->address = malloc(len);
            snprintf(bb->address, len, "%s:%s", pu->host, pu->port);
        } else if (pu->host) {
            bb->address = strdup(pu->host);
        }
        parsed_url_free(pu);
    }
    return bb;
}

static int glob_to_regex(const char *glob, char *regex, size_t regex_size) {
    size_t j = 0;
    if (j < regex_size - 1) regex[j++] = '^';
    for (size_t i = 0; glob[i]; i++) {
        if (glob[i] == '*') {
            if (j < regex_size - 1) regex[j++] = '.';
            if (j < regex_size - 1) regex[j++] = '*';
        } else if (glob[i] == '?') {
            if (j < regex_size - 1) regex[j++] = '.';
        } else if (glob[i] == 'Z' || glob[i] == 'z') {
            if (j < regex_size - 5) { regex[j++] = '['; regex[j++] = '1'; regex[j++] = '-'; regex[j++] = '9'; regex[j++] = ']'; }
        } else if (glob[i] == 'X' || glob[i] == 'x') {
            if (j < regex_size - 5) { regex[j++] = '['; regex[j++] = '0'; regex[j++] = '-'; regex[j++] = '9'; regex[j++] = ']'; }
        } else if (glob[i] == 'N' || glob[i] == 'n') {
        } else if (glob[i] == '.' || glob[i] == '^' || glob[i] == '$' ||
                   glob[i] == '\\' || glob[i] == '(' || glob[i] == ')' ||
                   glob[i] == '+' || glob[i] == '{' || glob[i] == '}' || glob[i] == '|') {
            if (j < regex_size - 1) regex[j++] = '\\';
            if (j < regex_size - 1) regex[j++] = glob[i];
        } else {
            if (j < regex_size - 1) regex[j++] = glob[i];
        }
    }
    if (j < regex_size - 1) regex[j++] = '$';
    regex[j] = '\0';
    return 0;
}

static struct trk_filter *parse_filter(const char *value) {
    struct trk_filter *f = calloc(1, sizeof(struct trk_filter));

    const char *p = value;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;

        const char *eq = strchr(p, '=');

        /* Find end of this token */
        const char *end;
        if (eq) {
            end = eq;
            while (*end && *end != ' ') end++;
        } else {
            /* No = sign: presence-only tag */
            end = p;
            while (*end && *end != ' ') end++;
        }

        f->tag_count++;
        f->tags = realloc(f->tags, f->tag_count * sizeof(struct trk_filter_tag));
        struct trk_filter_tag *t = &f->tags[f->tag_count - 1];

        /* Parse name */
        size_t name_len = eq ? (size_t)(eq - p) : (size_t)(end - p);
        t->name = malloc(name_len + 1);
        memcpy(t->name, p, name_len);
        t->name[name_len] = '\0';

        /* Parse value */
        t->value = NULL;
        t->is_glob = 0;
        memset(&t->compiled, 0, sizeof(t->compiled));

        if (eq) {
            const char *vstart = eq + 1;
            size_t val_len = (size_t)(end - vstart);

            if (val_len > 0 && vstart[0] == '/' && vstart[val_len - 1] == '/') {
                /* Regex: strip outer / delimiters */
                t->value = malloc(val_len - 1);
                memcpy(t->value, vstart + 1, val_len - 2);
                t->value[val_len - 2] = '\0';
                t->is_glob = 1;
                int rc = regcomp(&t->compiled, t->value, REG_EXTENDED | REG_NOSUB);
                if (rc != 0) {
                    char errbuf[256];
                    regerror(rc, &t->compiled, errbuf, sizeof(errbuf));
                    log_error("config: filter regex '/%s/': %s", t->value, errbuf);
                    t->is_glob = 0;
                }
            } else {
                t->value = malloc(val_len + 1);
                memcpy(t->value, vstart, val_len);
                t->value[val_len] = '\0';

                if (strcmp(t->name, "did") == 0 || strcmp(t->name, "cid") == 0) {
                    t->is_glob = 1;
                    char regex_str[512];
                    glob_to_regex(t->value, regex_str, sizeof(regex_str));
                    int rc = regcomp(&t->compiled, regex_str, REG_EXTENDED | REG_NOSUB);
                    if (rc != 0) {
                        char errbuf[256];
                        regerror(rc, &t->compiled, errbuf, sizeof(errbuf));
                        log_error("config: filter glob '%s': %s", t->value, errbuf);
                        t->is_glob = 0;
                    }
                }
            }
        }

        p = end;
    }

    return f;
}

static int config_handler(void *user, const char *section, const char *name, const char *value) {
    struct trk_config *cfg = user;

    if (strcmp(section, "trunk") == 0) {
        if (strcmp(name, "sip_port") == 0) {
            cfg->sip_port = atoi(value);
        } else if (strcmp(name, "rtp_range") == 0) {
            int min = 0, max = 0;
            if (sscanf(value, "%d-%d", &min, &max) == 2) {
                cfg->rtp_min = min;
                cfg->rtp_max = max;
            }
        } else if (strcmp(name, "delay") == 0) {
            cfg->delay_ms = atoi(value);
        } else if (strcmp(name, "listen_address") == 0) {
            free(cfg->listen_address);
            cfg->listen_address = strdup(value);
        } else if (strcmp(name, "target") == 0) {
            if (cfg->target) {
                free(cfg->target->url); free(cfg->target->scheme); free(cfg->target->host);
                free(cfg->target->port); free(cfg->target->path); free(cfg->target->address);
                free(cfg->target->username); free(cfg->target->password);
                free(cfg->target);
            }
            cfg->target = parse_backbone_url(value);
        } else if (is_numbered(name, "backbone")) {
            struct trk_backbone *bb = parse_backbone_url(value);
            bb->next = cfg->backbones;
            cfg->backbones = bb;
        } else if (strcmp(name, "filter") == 0) {
            struct trk_filter *f = parse_filter(value);
            f->next = cfg->filters;
            cfg->filters = f;
        }
    }

    return 1;
}

struct trk_config *trk_config_load(const char *path) {
    struct trk_config *cfg = calloc(1, sizeof(struct trk_config));
    if (!cfg) return NULL;

    cfg->sip_port = 5061;
    cfg->rtp_min = 20000;
    cfg->rtp_max = 30000;
    cfg->delay_ms = 1000;

    int ret = ini_parse(path, config_handler, cfg);
    if (ret < 0) {
        log_error("config: failed to parse %s: %s", path, ret == -1 ? "file not found" : "error");
        trk_config_free(cfg);
        return NULL;
    }

    return cfg;
}

static void free_backbone(struct trk_backbone *bb) {
    while (bb) {
        struct trk_backbone *next = bb->next;
        free(bb->url); free(bb->scheme); free(bb->host); free(bb->port);
        free(bb->path); free(bb->address); free(bb->username); free(bb->password);
        free(bb);
        bb = next;
    }
}

void trk_config_free(struct trk_config *cfg) {
    if (!cfg) return;

    free_backbone(cfg->backbones);
    free_backbone(cfg->target);

    struct trk_filter *f = cfg->filters;
    while (f) {
        struct trk_filter *next = f->next;
        for (int i = 0; i < f->tag_count; i++) {
            free(f->tags[i].name);
            free(f->tags[i].value);
            if (f->tags[i].is_glob) regfree(&f->tags[i].compiled);
        }
        free(f->tags);
        free(f);
        f = next;
    }

    free(cfg->listen_address);
    free(cfg);
}
