#include "domain/config.h"

#include <stdlib.h>
#include <string.h>

resp_object *domain_cfg = NULL;

void domain_config_init(void) {
  if (domain_cfg) return;
  domain_cfg = resp_array_init();
}

void domain_config_free(void) {
  if (domain_cfg) {
    resp_free(domain_cfg);
    domain_cfg = NULL;
  }
}
