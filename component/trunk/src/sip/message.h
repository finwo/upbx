#ifndef TRK_SIP_MESSAGE_H
#define TRK_SIP_MESSAGE_H

#include "sip/parser.h"

char *sip_build_response(int code, const char *reason,
                         struct sip_msg *orig,
                         const char *extra_headers,
                         const char *body, int body_len);

char *sip_build_401(struct sip_msg *orig, const char *nonce, const char *realm);

#endif
