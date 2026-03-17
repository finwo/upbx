#include "domain/pbx/routing.h"

#include <ctype.h>
#include <string.h>

#include "common/resp.h"
#include "domain/config.h"
#include "domain/pbx/extension.h"
#include "domain/pbx/registration.h"
#include "finwo/mindex.h"
#include "rxi/log.h"

int registration_is_pattern(const char *ext) {
  if (!ext) return 0;
  for (const char *p = ext; *p; p++) {
    if (*p == 'x' || *p == 'z' || *p == 'n' || *p == '.' || *p == '!') return 1;
  }
  return 0;
}

static int pattern_specificity(const char *pattern) {
  int score = 0;
  for (const char *p = pattern; *p; p++) {
    if (*p == '.')
      score += 1;
    else if (*p == '!')
      score += 2;
    else if (*p == 'x')
      score += 3;
    else if (*p == 'z')
      score += 4;
    else if (*p == 'n')
      score += 5;
    else if (isdigit(*p))
      score += 6;
  }
  return score;
}

int registration_match_pattern(const char *pattern, const char *number) {
  if (!pattern || !number) return 0;

  const char *pp = pattern;
  const char *np = number;

  while (*pp && *np) {
    if (*pp == 'x') {
      if (!isdigit((unsigned char)*np)) return 0;
    } else if (*pp == 'z') {
      if (*np < '1' || *np > '9') return 0;
    } else if (*pp == 'n') {
      if (*np < '2' || *np > '9') return 0;
    } else if (*pp == '.') {
      if (!isdigit((unsigned char)*np)) return 0;
      while (*np) np++;
      pp++;
      continue;
    } else if (*pp == '!') {
      while (*np) np++;
      pp++;
      continue;
    } else {
      if (*pp != *np) return 0;
    }
    pp++;
    np++;
  }

  if (*pp == '\0' && *np == '\0') return 1;
  if (*pp == '.' && *np == '\0') return 0;
  if (*pp == '!' && *np == '\0') return 1;

  return 0;
}

static int is_cross_group(const char *src_group, const char *dst_group) {
  if (!src_group || !dst_group) return 1;
  return strcmp(src_group, dst_group) != 0;
}

pbx_registration_t *pbx_route(const char *source_extension, const char *dialed_number,
                              const char *source_group_prefix) {
  pbx_extension_t *src_ext   = pbx_extension_find(source_extension);
  const char      *src_group = src_ext ? src_ext->group_prefix : NULL;

  char expanded[64] = {0};

  pbx_registration_t *exact_group_num    = NULL;
  pbx_registration_t *exact_num          = NULL;
  pbx_registration_t *best_pattern_group = NULL;
  pbx_registration_t *best_pattern_num   = NULL;
  int                 best_pattern_score = 0;

  if (source_group_prefix) {
    snprintf(expanded, sizeof(expanded), "%s%s", source_group_prefix, dialed_number);
    pbx_registration_t *reg = pbx_registration_find(expanded);
    if (reg) {
      pbx_extension_t *dst_ext   = pbx_extension_find(reg->extension);
      const char      *dst_group = dst_ext ? dst_ext->group_prefix : NULL;
      if (!is_cross_group(src_group, dst_group) ||
          (src_ext && src_group && pbx_group_find(src_group)->allow_outgoing_cross_group) || !src_ext) {
        exact_group_num = reg;
      }
    }
  }

  pbx_registration_t *reg = pbx_registration_find(dialed_number);
  if (reg) {
    pbx_extension_t *dst_ext   = pbx_extension_find(reg->extension);
    const char      *dst_group = dst_ext ? dst_ext->group_prefix : NULL;
    if (!is_cross_group(src_group, dst_group) ||
        (src_ext && src_group && pbx_group_find(src_group)->allow_outgoing_cross_group) || !src_ext) {
      exact_num = reg;
    }
  }

  log_trace("pbx: routing %s -> %s (src_group=%s)", source_extension, dialed_number, src_group ? src_group : "(none)");
  log_trace("pbx:   exact_group_num=%s, exact_num=%s", exact_group_num ? exact_group_num->extension : "none",
            exact_num ? exact_num->extension : "none");

  if (exact_group_num) {
    log_debug("pbx: routed to %s (exact group+number)", exact_group_num->extension);
    return exact_group_num;
  }

  if (exact_num) {
    log_debug("pbx: routed to %s (exact number)", exact_num->extension);
    return exact_num;
  }

  log_debug("pbx: no exact match, checking patterns");
  return NULL;
}

int pbx_is_emergency(const char *dialed_number) {
  if (!dialed_number || !domain_cfg) return 0;

  resp_object *upbx_sec = resp_map_get(domain_cfg, "upbx");
  if (!upbx_sec) return 0;

  resp_object *emerg_arr = resp_map_get(upbx_sec, "emergency");
  if (!emerg_arr || emerg_arr->type != RESPT_ARRAY) return 0;

  for (size_t i = 0; i < emerg_arr->u.arr.n; i++) {
    const char *num = NULL;
    if (emerg_arr->u.arr.elem[i].type == RESPT_BULK || emerg_arr->u.arr.elem[i].type == RESPT_SIMPLE) {
      num = emerg_arr->u.arr.elem[i].u.s;
    }
    if (num && strcmp(num, dialed_number) == 0) {
      log_info("pbx: dialed number '%s' is emergency", dialed_number);
      return 1;
    }
  }

  return 0;
}
