#ifndef UPBX_API_SERVER_H
#define UPBX_API_SERVER_H

#include <stdbool.h>
#include <stdint.h>

#include "common/resp.h"
#include "common/scheduler.h"

struct api_client_state;
typedef struct api_client_state api_client_t;

typedef resp_object *(*domain_cmd_fn)(const char *cmd, resp_object *args);

int api_server_pt(int64_t timestamp, struct pt_task *task);
int api_client_pt(int64_t timestamp, struct pt_task *task);

void api_register_cmd(const char *name, char (*func)(api_client_t *, char **, int));

void api_register_domain_cmd(const char *name, domain_cmd_fn func);

bool api_write_ok(api_client_t *c);
bool api_write_err(api_client_t *c, const char *msg);
bool api_write_array(api_client_t *c, size_t nitems);
bool api_write_bulk_cstr(api_client_t *c, const char *s);
bool api_write_bulk_int(api_client_t *c, int val);
bool api_write_int(api_client_t *c, int val);

#endif
