#include "pbx/dialplan.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pattern_char_score(char c) {
  if (c >= '0' && c <= '9') return 12;
  if (c == 'z') return 9;
  if (c == 'n') return 8;
  if (c == 'x') return 5;
  if (c == '[') return 4;
  if (c == '.') return 3;
  if (c == '!') return 2;
  if (c == '*') return 1;
  return 0;
}

static int match_pattern(const char *pattern, const char *number) {
  size_t plen = strlen(pattern);
  size_t nlen = strlen(number);

  size_t pi = 0, ni = 0;
  int score = 0;
  int has_bracket = 0;
  char bracket_chars[16] = {0};
  size_t bracket_pos = 0;

  while (pi < plen && ni < nlen) {
    char pc = pattern[pi];
    char nc = number[ni];

    if (pc == '[') {
      has_bracket = 1;
      bracket_pos = 0;
      pi++;
      continue;
    }

    if (has_bracket) {
      if (pc == ']') {
        has_bracket = 0;
        bracket_chars[bracket_pos] = '\0';
        pi++;
        int found = 0;
        for (size_t j = 0; j < strlen(bracket_chars); j++) {
          if (bracket_chars[j] == nc) {
            found = 1;
            break;
          }
        }
        if (!found) return -1;
        score += 4;
        ni++;
        pi++;
        continue;
      }
      if (bracket_pos < 15) {
        if (pc == '-' && bracket_pos > 0) {
          char start = bracket_chars[bracket_pos - 1];
          char end = pattern[pi + 1];
          if (end >= start && nc >= start && nc <= end) {
            for (char c = start; c <= end; c++) {
              bracket_chars[bracket_pos++] = c;
            }
          }
        } else {
          bracket_chars[bracket_pos++] = pc;
        }
      }
      pi++;
      continue;
    }

    if (pc == 'x' || pc == 'n' || pc == 'z' || pc == '*' || pc == '.' || pc == '!') {
      score += pattern_char_score(pc);
      if (pc == '.') {
        while (ni < nlen) {
          ni++;
        }
        break;
      }
      if (pc == '!') {
        break;
      }
      ni++;
      pi++;
      continue;
    }

    if (pc == nc) {
      score += 12;
      ni++;
      pi++;
      continue;
    }

    return -1;
  }

  while (pi < plen) {
    char pc = pattern[pi];
    if (pc == '*' || pc == '!' || pc == '.') {
      break;
    }
    return -1;
  }

  if (ni < nlen) {
    return -1;
  }

  return score;
}

int dialplan_match_extension(const char *dialed_number, const char *group_prefix, struct upbx_extension **matches, size_t *match_count) {
  (void)group_prefix;
  *matches = NULL;
  *match_count = 0;

  return 0;
}

int dialplan_is_emergency(struct upbx_config *config, const char *number) {
  if (!config || !number) return 0;

  for (size_t i = 0; i < config->n_emergency_numbers; i++) {
    const char *emergency = config->emergency_numbers[i];
    if (strcmp(emergency, number) == 0) {
      return 1;
    }
  }

  return 0;
}

static int can_call_group(struct upbx_config *config, const char *from_group, const char *to_group, int outgoing) {
  if (!from_group || !to_group) return 0;
  if (strcmp(from_group, to_group) == 0) return 1;

  struct upbx_group *from = NULL;
  for (struct upbx_group *g = config->groups; g; g = g->next) {
    if (strcmp(g->id, from_group) == 0) {
      from = g;
      break;
    }
  }

  if (!from) return 0;

  return outgoing ? from->allow_outgoing_cross_group : from->allow_incoming_cross_group;
}

int dialplan_route(struct upbx_config *config, const char *caller_group, const char *dialed_number, struct dialplan_result *result) {
  if (!config || !dialed_number || !result) return -1;

  memset(result, 0, sizeof(*result));

  int is_emergency = dialplan_is_emergency(config, dialed_number);
  if (is_emergency) {
    result->is_emergency = 1;
    return 0;
  }

  struct upbx_extension *best_ext = NULL;
  int best_score = -1;
  char *best_attempt = NULL;

  const char *attempts[2] = {NULL, NULL};

  if (caller_group) {
    size_t len = strlen(caller_group) + strlen(dialed_number) + 1;
    char *group_attempt = malloc(len);
    snprintf(group_attempt, len, "%s%s", caller_group, dialed_number);
    attempts[0] = group_attempt;
  }
  attempts[1] = dialed_number;

  for (int a = 0; a < 2 && attempts[a]; a++) {
    const char *attempt = attempts[a];

    for (struct upbx_extension *e = config->extensions; e; e = e->next) {
      if (!e->group) continue;

      if (caller_group && strcmp(caller_group, e->group) != 0) {
        if (!can_call_group(config, caller_group, e->group, 1)) {
          continue;
        }
      }

      int score = match_pattern(e->id, attempt);
      if (score < 0) continue;

      if (score > best_score) {
        best_score = score;
        best_ext = e;
        best_attempt = (char *)attempt;
      }
    }

    if (a == 0 && attempts[0]) {
      free((char *)attempts[0]);
    }
  }

  if (best_ext) {
    result->target = strdup(best_ext->id);
    result->is_trunk = 0;
    return 0;
  }

  if (!caller_group) {
    return -1;
  }

  size_t trunk_count = 0;
  struct upbx_trunk **trunks = upbx_config_find_trunks_by_group(config, caller_group, &trunk_count);

  if (trunks && trunk_count > 0) {
    result->target = strdup(trunks[0]->name);
    result->is_trunk = 1;
    free(trunks);
    return 0;
  }

  return -1;
}
