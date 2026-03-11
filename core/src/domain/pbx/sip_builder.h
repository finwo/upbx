#ifndef UPBX_PBX_SIP_BUILDER_H
#define UPBX_PBX_SIP_BUILDER_H

#include "domain/pbx/sip_parser.h"

char *sip_build_message(int status_code, const char *reason, const sip_message_t *req, const char *extra_headers,
                        const char *body);

#endif
