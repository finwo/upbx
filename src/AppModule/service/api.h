/*
 * Generic RESP2 API server: TCP listener with command dispatch,
 * authentication, and per-user permission checking.
 *
 * Runs as a protothread in the main select() loop.
 * Other modules register commands via api_register_cmd().
 */
#ifndef UPBX_SERVICE_API_H
#define UPBX_SERVICE_API_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/select.h>
#include "common/pt.h"

struct upbx_config;

/* Client handle (opaque to command implementations) */
typedef struct api_client api_client_t;

/* Command handler signature.
 * args[0] = command name (lowercased), args[1..nargs-1] = arguments.
 * Return true to keep connection open, false to close it. */
typedef bool (*api_cmd_func)(api_client_t *c, struct upbx_config *cfg, char **args, int nargs);

/* Register a command with the API server. Call from module init (before api_start). */
void api_register_cmd(const char *name, api_cmd_func func);

/* Write helpers (exposed for use by command handlers) */
bool api_write_raw(api_client_t *c, const void *data, size_t len);
bool api_write_cstr(api_client_t *c, const char *s);
bool api_write_ok(api_client_t *c);
bool api_write_err(api_client_t *c, const char *msg);
bool api_write_nil(api_client_t *c);
bool api_write_int(api_client_t *c, int value);
bool api_write_array(api_client_t *c, size_t nitems);
bool api_write_bulk_cstr(api_client_t *c, const char *s);
bool api_write_bulk_int(api_client_t *c, int val);
bool api_write_bulk_time(api_client_t *c, long t);
bool api_write_kv(api_client_t *c, const char *key, const char *val);
bool api_write_kv_int(api_client_t *c, const char *key, int val);
bool api_write_kv_time(api_client_t *c, const char *key, long t);

/* Lifecycle + protothread */
void api_start(struct upbx_config *cfg);
void api_fill_fds(fd_set *read_set, int *maxfd);
PT_THREAD(api_pt(struct pt *pt, fd_set *read_set, struct upbx_config *cfg));
void api_stop(void);

#endif
