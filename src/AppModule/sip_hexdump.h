#ifndef UPBX_SIP_HEXDUMP_H
#define UPBX_SIP_HEXDUMP_H

#include <stddef.h>

/* Log buf[0..len) as canonical hexdump at trace level (e.g. before sending to libosip2). */
void log_hexdump_trace(const char *buf, size_t len);

#endif
