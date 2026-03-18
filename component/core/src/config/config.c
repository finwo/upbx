#include "config/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "benhoyt/inih.h"
#include "finwo/url-parser.h"

static struct upbx_config *g_config = NULL;

static char *strdup_or_null(const char *s) {
  return s ? strdup(s) : NULL;
}

static void free_group(struct upbx_group *g) {
  if (!g) return;
  free(g->id);
  free(g);
}

static void free_extension(struct upbx_extension *e) {
  if (!e) return;
  free(e->id);
  free(e->name);
  free(e->secret);
  free(e->group);
  free(e->pbx_addr);
  free(e->contact);
  free(e);
}

static void free_trunk_rewrite(struct upbx_trunk_rewrite *r) {
  if (!r) return;
  free(r->pattern);
  free(r->replace);
  free(r);
}

static void free_trunk(struct upbx_trunk *t) {
  if (!t) return;
  free(t->name);
  if (t->address) parsed_url_free(t->address);
  for (size_t i = 0; i < t->n_dids; i++) free(t->dids[i]);
  free(t->dids);
  free(t->cid);
  for (size_t i = 0; i < t->n_groups; i++) free(t->groups[i]);
  free(t->groups);
  struct upbx_trunk_rewrite *r = t->rewrites;
  while (r) {
    struct upbx_trunk_rewrite *next = r->next;
    free_trunk_rewrite(r);
    r = next;
  }
  free(t->registered_contact);
  free(t);
}

static void free_rtpproxy(struct upbx_rtpproxy *r) {
  if (!r) return;
  if (r->url) parsed_url_free(r->url);
  free(r);
}

static int config_ini_handler(void *user, const char *section, const char *name, const char *value) {
  (void)user;

  struct upbx_config *cfg = g_config;
  if (!cfg) return 0;

  if (strcmp(section, "upbx") == 0) {
    if (strcmp(name, "address") == 0) {
      free(cfg->address);
      cfg->address = strdup(value);
    } else if (strcmp(name, "daemonize") == 0) {
      cfg->daemonize = (strcmp(value, "1") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0);
    } else if (strcmp(name, "data_dir") == 0) {
      free(cfg->data_dir);
      cfg->data_dir = strdup(value);
    } else if (strcmp(name, "rtpproxy") == 0) {
      struct parsed_url *url = parse_url(value);
      if (!url) {
        fprintf(stderr, "config: failed to parse rtpproxy URL '%s'\n", value);
        return 0;
      }
      struct upbx_rtpproxy *rtp = malloc(sizeof(*rtp));
      rtp->url = url;
      rtp->next = NULL;

      if (!cfg->rtpproxies) {
        cfg->rtpproxies = rtp;
        cfg->rtpproxy_current = rtp;
      } else {
        cfg->rtpproxy_current->next = rtp;
        cfg->rtpproxy_current = rtp;
      }
    } else if (strcmp(name, "emergency") == 0) {
      cfg->emergency_numbers = realloc(cfg->emergency_numbers, sizeof(char *) * (cfg->n_emergency_numbers + 1));
      cfg->emergency_numbers[cfg->n_emergency_numbers++] = strdup(value);
    }
  } else if (strncmp(section, "group:", 6) == 0) {
    const char *group_id = section + 6;
    struct upbx_group *group = malloc(sizeof(*group));
    group->id = strdup(group_id);
    group->allow_outgoing_cross_group = false;
    group->allow_incoming_cross_group = false;
    group->next = NULL;

    if (strcmp(name, "allow_outgoing_cross_group") == 0) {
      group->allow_outgoing_cross_group = (strcmp(value, "1") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0);
    } else if (strcmp(name, "allow_incoming_cross_group") == 0) {
      group->allow_incoming_cross_group = (strcmp(value, "1") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0);
    }

    struct upbx_group **tail = &cfg->groups;
    while (*tail) tail = &(*tail)->next;
    *tail = group;
  } else if (strncmp(section, "ext:", 4) == 0) {
    const char *ext_id = section + 4;
    struct upbx_extension *ext = NULL;
    for (struct upbx_extension *e = cfg->extensions; e; e = e->next) {
      if (strcmp(e->id, ext_id) == 0) {
        ext = e;
        break;
      }
    }
    if (!ext) {
      ext = malloc(sizeof(*ext));
      ext->id = strdup(ext_id);
      ext->name = NULL;
      ext->secret = NULL;
      ext->group = NULL;
      memset(&ext->remote_addr, 0, sizeof(ext->remote_addr));
      ext->pbx_addr = NULL;
      ext->contact = NULL;
      ext->expires = 0;
      ext->next = NULL;

      struct upbx_extension **tail = &cfg->extensions;
      while (*tail) tail = &(*tail)->next;
      *tail = ext;
    }

    if (strcmp(name, "name") == 0) {
      free(ext->name);
      ext->name = strdup(value);
    } else if (strcmp(name, "secret") == 0) {
      free(ext->secret);
      ext->secret = strdup(value);
    } else if (strcmp(name, "group") == 0) {
      free(ext->group);
      ext->group = strdup(value);
    }
  } else if (strncmp(section, "trunk:", 6) == 0) {
    const char *trunk_name = section + 6;
    struct upbx_trunk *trunk = NULL;
    for (struct upbx_trunk *t = cfg->trunks; t; t = t->next) {
      if (strcmp(t->name, trunk_name) == 0) {
        trunk = t;
        break;
      }
    }
    if (!trunk) {
      trunk = malloc(sizeof(*trunk));
      trunk->name = strdup(trunk_name);
      trunk->address = NULL;
      trunk->dids = NULL;
      trunk->n_dids = 0;
      trunk->cid = NULL;
      trunk->groups = NULL;
      trunk->n_groups = 0;
      trunk->rewrites = NULL;
      trunk->registered_contact = NULL;
      trunk->next = NULL;

      struct upbx_trunk **tail = &cfg->trunks;
      while (*tail) tail = &(*tail)->next;
      *tail = trunk;
    }

    if (strcmp(name, "address") == 0) {
      if (trunk->address) parsed_url_free(trunk->address);
      trunk->address = parse_url(value);
    } else if (strcmp(name, "did") == 0) {
      trunk->dids = realloc(trunk->dids, sizeof(char *) * (trunk->n_dids + 1));
      trunk->dids[trunk->n_dids++] = strdup(value);
    } else if (strcmp(name, "cid") == 0) {
      free(trunk->cid);
      trunk->cid = strdup(value);
    } else if (strcmp(name, "group") == 0) {
      trunk->groups = realloc(trunk->groups, sizeof(char *) * (trunk->n_groups + 1));
      trunk->groups[trunk->n_groups++] = strdup(value);
    } else if (strcmp(name, "rewrite_pattern") == 0) {
      struct upbx_trunk_rewrite *r = malloc(sizeof(*r));
      r->pattern = strdup(value);
      r->replace = NULL;
      r->next = NULL;

      if (!trunk->rewrites) {
        trunk->rewrites = r;
      } else {
        struct upbx_trunk_rewrite *last = trunk->rewrites;
        while (last->next) last = last->next;
        last->next = r;
      }
    } else if (strcmp(name, "rewrite_replace") == 0) {
      struct upbx_trunk_rewrite *r = trunk->rewrites;
      if (r) {
        while (r->next) r = r->next;
        free(r->replace);
        r->replace = strdup(value);
      }
    }
  }

  return 1;
}

struct upbx_config *upbx_config_load(const char *filename) {
  struct upbx_config *cfg = calloc(1, sizeof(*cfg));

  cfg->address = strdup(":5060");
  cfg->daemonize = false;
  cfg->data_dir = strdup("/var/lib/upbx");

  g_config = cfg;

  int ret = ini_parse(filename, config_ini_handler, NULL);
  if (ret < 0) {
    fprintf(stderr, "config: failed to parse '%s'\n", filename);
    upbx_config_free(cfg);
    return NULL;
  }

  if (cfg->rtpproxies && cfg->rtpproxy_current) {
    fprintf(stderr, "DEBUG config: setting up circular list for rtpproxies\n");
    fflush(stderr);
    cfg->rtpproxy_current->next = cfg->rtpproxies;
    cfg->rtpproxy_current = cfg->rtpproxies;
    fprintf(stderr, "DEBUG config: rtpproxies setup done\n");
    fflush(stderr);
  } else {
    fprintf(stderr, "DEBUG config: no rtpproxies set (rtpproxies=%p, rtpproxy_current=%p)\n", (void*)cfg->rtpproxies, (void*)cfg->rtpproxy_current);
    fflush(stderr);
  }

  for (struct upbx_extension *e = cfg->extensions; e; e = e->next) {
    if (!e->group) {
      struct upbx_group *best_group = NULL;
      size_t best_len = 0;
      for (struct upbx_group *g = cfg->groups; g; g = g->next) {
        size_t glen = strlen(g->id);
        if (glen > best_len && strncmp(e->id, g->id, glen) == 0) {
          best_group = g;
          best_len = glen;
        }
      }
      if (best_group) {
        e->group = strdup(best_group->id);
      }
    }
  }

  g_config = NULL;
  return cfg;
}

void upbx_config_free(struct upbx_config *cfg) {
  if (!cfg) return;

  free(cfg->address);
  free(cfg->data_dir);

  for (size_t i = 0; i < cfg->n_emergency_numbers; i++) {
    free(cfg->emergency_numbers[i]);
  }
  free(cfg->emergency_numbers);

  struct upbx_rtpproxy *r = cfg->rtpproxies;
  while (r) {
    struct upbx_rtpproxy *next = r->next;
    free_rtpproxy(r);
    r = next;
  }

  struct upbx_group *g = cfg->groups;
  while (g) {
    struct upbx_group *next = g->next;
    free_group(g);
    g = next;
  }

  struct upbx_extension *e = cfg->extensions;
  while (e) {
    struct upbx_extension *next = e->next;
    free_extension(e);
    e = next;
  }

  struct upbx_trunk *t = cfg->trunks;
  while (t) {
    struct upbx_trunk *next = t->next;
    free_trunk(t);
    t = next;
  }

  free(cfg);
}

const char *upbx_config_get_emergency_number(const struct upbx_config *cfg, size_t idx) {
  if (!cfg || idx >= cfg->n_emergency_numbers) return NULL;
  return cfg->emergency_numbers[idx];
}

size_t upbx_config_get_emergency_count(const struct upbx_config *cfg) {
  return cfg ? cfg->n_emergency_numbers : 0;
}

struct upbx_group *upbx_config_find_group_by_prefix(const struct upbx_config *cfg, const char *ext_id) {
  if (!cfg || !ext_id) return NULL;

  struct upbx_group *best = NULL;
  size_t best_len = 0;

  for (struct upbx_group *g = cfg->groups; g; g = g->next) {
    size_t glen = strlen(g->id);
    if (glen > best_len && strncmp(ext_id, g->id, glen) == 0) {
      best = g;
      best_len = glen;
    }
  }

  return best;
}

struct upbx_extension *upbx_config_find_extension(const struct upbx_config *cfg, const char *ext_id) {
  if (!cfg || !ext_id) return NULL;
  for (struct upbx_extension *e = cfg->extensions; e; e = e->next) {
    if (strcmp(e->id, ext_id) == 0) return e;
  }
  return NULL;
}

struct upbx_extension *upbx_config_find_extension_by_addr(const struct upbx_config *cfg, const struct sockaddr_storage *addr) {
  if (!cfg || !addr) return NULL;
  for (struct upbx_extension *e = cfg->extensions; e; e = e->next) {
    if (memcmp(&e->remote_addr, addr, sizeof(*addr)) == 0) return e;
  }
  return NULL;
}

struct upbx_trunk *upbx_config_find_trunk(const struct upbx_config *cfg, const char *trunk_name) {
  if (!cfg || !trunk_name) return NULL;
  for (struct upbx_trunk *t = cfg->trunks; t; t = t->next) {
    if (strcmp(t->name, trunk_name) == 0) return t;
  }
  return NULL;
}

struct upbx_trunk **upbx_config_find_trunks_by_group(const struct upbx_config *cfg, const char *group, size_t *count) {
  if (!cfg || !group || !count) return NULL;

  size_t capacity = 8;
  struct upbx_trunk **results = malloc(sizeof(*results) * capacity);
  *count = 0;

  for (struct upbx_trunk *t = cfg->trunks; t; t = t->next) {
    for (size_t i = 0; i < t->n_groups; i++) {
      if (strcmp(t->groups[i], group) == 0) {
        if (*count >= capacity) {
          capacity *= 2;
          results = realloc(results, sizeof(*results) * capacity);
        }
        results[(*count)++] = t;
        break;
      }
    }
  }

  return results;
}

char *upbx_config_trunk_rewrite(const struct upbx_trunk *trunk, const char *number) {
  if (!trunk || !number) return NULL;

  for (struct upbx_trunk_rewrite *r = trunk->rewrites; r; r = r->next) {
    if (!r->pattern || !r->replace) continue;

    const char *p = number;
    size_t plen = strlen(r->pattern);

    while (*p) {
      if (strncmp(p, r->pattern, plen) == 0) {
        size_t num_len = strlen(number);
        size_t pat_len = strlen(r->pattern);
        size_t rep_len = strlen(r->replace);

        char *result = malloc(num_len - pat_len + rep_len + 1);
        size_t offset = p - number;

        memcpy(result, number, offset);
        memcpy(result + offset, r->replace, rep_len);
        strcpy(result + offset + rep_len, p + pat_len);

        return result;
      }
      p++;
    }
  }

  return strdup(number);
}
