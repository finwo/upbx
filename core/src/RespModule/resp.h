/*
 * RESP (Redis Serialization Protocol) encoding and decoding.
 * Types and helpers for building/parsing RESP values.
 */
#ifndef RESPMODULE_RESP_H
#define RESPMODULE_RESP_H

#include <stddef.h>

#define RESPT_SIMPLE  0
#define RESPT_ERROR   1
#define RESPT_BULK    2
#define RESPT_INT      3
#define RESPT_ARRAY    4

/* RESP value. Call resp_free when done. */
typedef struct resp_object resp_object;
struct resp_object {
  int type;  /* RESPT_* */
  union {
    char *s;
    long long i;
    struct { resp_object *elem; size_t n; } arr;
  } u;
};

void resp_free(resp_object *o);

/* Deep-copy resp_object. Caller must resp_free result. Returns NULL on alloc failure. */
resp_object *resp_deep_copy(const resp_object *o);

/* Map helper: array as map (even-length: key, value, ...). Returns value element or NULL. Valid until resp freed. */
resp_object *resp_map_get(const resp_object *o, const char *key);

/* Map + key → string value (BULK/SIMPLE), or NULL. Valid until resp freed. */
const char *resp_map_get_string(const resp_object *o, const char *key);

/* Decode one RESP value from fd. Caller must resp_free result. Returns NULL on error. */
resp_object *resp_read(int fd);

/* Encode array of argc objects. Caller must free(*out_buf). Returns 0 on success. */
int resp_encode_array(int argc, const resp_object *const *argv, char **out_buf, size_t *out_len);

/* Allocate an empty RESPT_ARRAY. Caller must resp_free. Returns NULL on alloc failure. */
resp_object *resp_array_init(void);

/* Append value to array (destination must be RESPT_ARRAY). Takes ownership of value; no clone. Returns 0 on success. */
int resp_array_append_obj(resp_object *destination, resp_object *value);

/* Append string/integer to array (clone string for simple/bulk). Return 0 on success. */
int resp_array_append_simple(resp_object *destination, const char *str);
int resp_array_append_bulk(resp_object *destination, const char *str);
int resp_array_append_int(resp_object *destination, long long i);

#endif
