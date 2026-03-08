#ifndef UPBX_PBX_EXTENSION_H
#define UPBX_PBX_EXTENSION_H

#include <stddef.h>

typedef struct {
  char *prefix;
  int allow_incoming_cross_group;
  int allow_outgoing_cross_group;
} pbx_group_t;

typedef struct {
  char *number;
  char *secret;
  char *name;
  char *group_prefix;
} pbx_extension_t;

void pbx_extension_init(void);
void pbx_extension_shutdown(void);

pbx_extension_t *pbx_extension_find(const char *number);
pbx_group_t *pbx_group_find(const char *prefix);

#endif
