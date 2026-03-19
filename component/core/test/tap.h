#ifndef UPBX_TAP_H
#define UPBX_TAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(msg, cond) do { \
    tap_asserts++; \
    if (cond) { tap_passes++; printf("ok %d - %s\n", tap_asserts, msg); } \
    else { tap_fails++; printf("not ok %d - %s\n", tap_asserts, msg); failed = 1; } \
} while(0)

#define ASSERT_STR(expected, actual) do { \
    tap_asserts++; \
    int match = (expected) && (actual) && strcmp(expected, actual) == 0; \
    if (match) { tap_passes++; printf("ok %d - '%s' == '%s'\n", tap_asserts, expected, actual); } \
    else { tap_fails++; printf("not ok %d - '%s' != '%s'\n", tap_asserts, expected ? expected : "(null)", actual ? actual : "(null)"); failed = 1; } \
} while(0)

#define ASSERT_PREFIX(prefix, actual) do { \
    tap_asserts++; \
    int match = (prefix) && (actual) && strncmp(prefix, actual, strlen(prefix)) == 0; \
    if (match) { tap_passes++; printf("ok %d - '%s' starts with '%s'\n", tap_asserts, actual ? actual : "", prefix); } \
    else { tap_fails++; printf("not ok %d - '%s' does not start with '%s'\n", tap_asserts, actual ? actual : "", prefix); failed = 1; } \
} while(0)

#define ASSERT_DATA(data, datalen) do { \
    tap_asserts++; \
    if (datalen > 0) { tap_passes++; printf("ok %d - data len %zu\n", tap_asserts, (size_t)datalen); } \
    else { tap_fails++; printf("not ok %d - no data\n", tap_asserts); failed = 1; } \
} while(0)

#define RUN(name) do { printf("# %s\n", name); name(); } while(0)

int tap_asserts = 0;
int tap_passes = 0;
int tap_fails = 0;
int failed = 0;

int tap_report(void) {
    printf("1..%d\n", tap_asserts);
    printf("# pass %d, fail %d\n", tap_passes, tap_fails);
    return tap_fails > 0 ? 1 : 0;
}

#endif
