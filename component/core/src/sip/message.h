#ifndef SIP_MESSAGE_H
#define SIP_MESSAGE_H

#include <stddef.h>

#include "sip/parser.h"

char *sip_build_response(const struct sip_response *resp, size_t *out_len);
char *sip_build_request(enum sip_method method, const char *uri, const char *from, const char *to, const char *call_id, const char *cseq, const char *contact, const char *via, const char *branch, const char *body, size_t body_len, size_t *out_len);

#endif // SIP_MESSAGE_H
