#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config/config.h"
#include "benhoyt/inih.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"

#define MAX_REWRITE_RULES 32

static char *rewrite_desc[MAX_REWRITE_RULES];
static char *rewrite_pattern[MAX_REWRITE_RULES];
static char *rewrite_replace[MAX_REWRITE_RULES];
static int rewrite_count = 0;

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

static int config_handler(void *user, const char *section, const char *name, const char *value) {
    struct gw_config *cfg = user;

    if (strcmp(section, "gw") == 0) {
        if (strcmp(name, "sip_port") == 0) {
            cfg->sip_port = atoi(value);
        } else if (strcmp(name, "rtp_range") == 0) {
            int min = 0, max = 0;
            if (sscanf(value, "%d-%d", &min, &max) == 2) {
                cfg->rtp_min = min;
                cfg->rtp_max = max;
            }
        } else if (strcmp(name, "cid") == 0) {
            cfg->cid = strdup(value);
        } else if (is_numbered(name, "did")) {
            struct gw_did *d = calloc(1, sizeof(struct gw_did));
            d->did = strdup(value);
            d->next = cfg->dids;
            cfg->dids = d;
        } else if (is_numbered(name, "backbone")) {
            struct gw_backbone *bb = calloc(1, sizeof(struct gw_backbone));
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
            bb->next = cfg->backbones;
            cfg->backbones = bb;
        } else if (is_numbered(name, "rewrite_desc")) {
            if (rewrite_count < MAX_REWRITE_RULES) {
                free(rewrite_desc[rewrite_count]);
                rewrite_desc[rewrite_count] = strdup(value);
            }
        } else if (is_numbered(name, "rewrite_pattern")) {
            if (rewrite_count < MAX_REWRITE_RULES) {
                free(rewrite_pattern[rewrite_count]);
                rewrite_pattern[rewrite_count] = strdup(value);
                rewrite_count++;
            }
        } else if (is_numbered(name, "rewrite_replace")) {
            if (rewrite_count > 0 && rewrite_count <= MAX_REWRITE_RULES) {
                free(rewrite_replace[rewrite_count - 1]);
                rewrite_replace[rewrite_count - 1] = strdup(value);
            }
        }
    } else if (strncmp(section, "ext:", 4) == 0) {
        const char *ext_num = section + 4;
        /* Find or create extension entry */
        struct gw_ext *ext = NULL;
        for (struct gw_ext *e = cfg->extensions; e; e = e->next) {
            if (strcmp(e->extension, ext_num) == 0) {
                ext = e;
                break;
            }
        }
        if (!ext) {
            ext = calloc(1, sizeof(struct gw_ext));
            ext->extension = strdup(ext_num);
            ext->next = cfg->extensions;
            cfg->extensions = ext;
        }
        if (strcmp(name, "secret") == 0) {
            free(ext->secret);
            ext->secret = strdup(value);
        }
    }

    return 1;
}

struct gw_config *gw_config_load(const char *path) {
    struct gw_config *cfg = calloc(1, sizeof(struct gw_config));
    if (!cfg) return NULL;

    cfg->sip_port = 5060;
    cfg->rtp_min = 10000;
    cfg->rtp_max = 20000;

    /* Reset static rewrite arrays */
    memset(rewrite_desc, 0, sizeof(rewrite_desc));
    memset(rewrite_pattern, 0, sizeof(rewrite_pattern));
    memset(rewrite_replace, 0, sizeof(rewrite_replace));
    rewrite_count = 0;

    int ret = ini_parse(path, config_handler, cfg);
    if (ret < 0) {
        log_error("config: failed to parse %s: %s", path, ret == -1 ? "file not found" : "error");
        gw_config_free(cfg);
        return NULL;
    }

    /* Compile rewrite rules and build linked list (reverse order since they were prepended) */
    for (int i = 0; i < rewrite_count; i++) {
        if (!rewrite_pattern[i]) continue;

        struct gw_rewrite_rule *rule = calloc(1, sizeof(struct gw_rewrite_rule));
        rule->desc = rewrite_desc[i];       /* ownership transferred */
        rule->pattern_str = rewrite_pattern[i]; /* ownership transferred */
        rule->replace_str = rewrite_replace[i]; /* ownership transferred */
        rewrite_desc[i] = NULL;
        rewrite_pattern[i] = NULL;
        rewrite_replace[i] = NULL;

        int rc = regcomp(&rule->compiled, rule->pattern_str, REG_EXTENDED | REG_ICASE);
        if (rc != 0) {
            char errbuf[256];
            regerror(rc, &rule->compiled, errbuf, sizeof(errbuf));
            log_error("config: rewrite rule '%s': %s", rule->pattern_str, errbuf);
            free(rule->desc);
            free(rule->pattern_str);
            free(rule->replace_str);
            free(rule);
            continue;
        }

        rule->next = cfg->rewrite_rules;
        cfg->rewrite_rules = rule;
    }

    /* Clean up any unclaimed static array entries */
    for (int i = 0; i < rewrite_count; i++) {
        free(rewrite_desc[i]);
        free(rewrite_pattern[i]);
        free(rewrite_replace[i]);
    }

    return cfg;
}

void gw_config_free(struct gw_config *cfg) {
    if (!cfg) return;

    struct gw_did *d = cfg->dids;
    while (d) {
        struct gw_did *next = d->next;
        free(d->did);
        free(d);
        d = next;
    }

    struct gw_backbone *bb = cfg->backbones;
    while (bb) {
        struct gw_backbone *next = bb->next;
        free(bb->url); free(bb->scheme); free(bb->host); free(bb->port);
        free(bb->path); free(bb->address); free(bb->username); free(bb->password);
        free(bb);
        bb = next;
    }

    struct gw_ext *ext = cfg->extensions;
    while (ext) {
        struct gw_ext *next = ext->next;
        free(ext->extension); free(ext->secret); free(ext->pbx_addr); free(ext->contact);
        free(ext);
        ext = next;
    }

    struct gw_rewrite_rule *rr = cfg->rewrite_rules;
    while (rr) {
        struct gw_rewrite_rule *next = rr->next;
        regfree(&rr->compiled);
        free(rr->desc); free(rr->pattern_str); free(rr->replace_str);
        free(rr);
        rr = next;
    }

    free(cfg->cid);
    free(cfg);
}

struct gw_ext *gw_config_find_ext(struct gw_config *cfg, const char *ext) {
    for (struct gw_ext *e = cfg->extensions; e; e = e->next) {
        if (strcmp(e->extension, ext) == 0) return e;
    }
    return NULL;
}
