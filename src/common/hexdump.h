/*
 * Canonical hexdump utility for debugging network buffers.
 */
#ifndef UPBX_HEXDUMP_H
#define UPBX_HEXDUMP_H

#include <stddef.h>

/* Log buf[0..len) as canonical hexdump at trace level. */
void log_hexdump_trace(const char *buf, size_t len);

#endif
