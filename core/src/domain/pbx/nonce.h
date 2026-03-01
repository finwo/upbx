#ifndef UPBX_PBX_NONCE_H
#define UPBX_PBX_NONCE_H

#include <stddef.h>

void nonce_set_secret(const char *secret);

const char *nonce_get_secret(void);

void nonce_generate(const char *ext_number, char *out, size_t out_size);

int nonce_validate(const char *nonce, const char *ext_number);

#endif
