#ifndef UDPHOLE_RESP_H
#define UDPHOLE_RESP_H

#include <stddef.h>

#define RESPT_SIMPLE 0
#define RESPT_ERROR  1
#define RESPT_BULK   2
#define RESPT_INT    3
#define RESPT_ARRAY  4

typedef struct resp_object resp_object;
struct resp_object {
  int type;
  union {
    char     *s;
    long long i;
    struct {
      resp_object *elem;
      size_t       n;
    } arr;
  } u;
};

void resp_free(resp_object *o);
/* Takes ownership: frees the object and all nested data */

resp_object *resp_deep_copy(const resp_object *o);
/* Returns new object: caller owns the result, must call resp_free() */

resp_object *resp_map_get(const resp_object *o, const char *key);
/* Returns pointer into o: caller must NOT call resp_free() on result */

const char *resp_map_get_string(const resp_object *o, const char *key);
/* Returns pointer into o: caller must NOT free the result */

void resp_map_set(resp_object *map, const char *key, resp_object *value);
/* Takes ownership of value */

resp_object *resp_read(int fd);
/* Returns new object: caller owns the result, must call resp_free() */

resp_object *resp_read_buf(const char *buf, size_t len);
/* Returns new object: caller owns the result, must call resp_free() */

int resp_encode_array(int argc, const resp_object *const *argv, char **out_buf, size_t *out_len);
/* Returns allocated string in out_buf: caller must free() the string */

int resp_serialize(const resp_object *o, char **out_buf, size_t *out_len);
/* Returns allocated string in out_buf: caller must free() the string */

resp_object *resp_array_init(void);
/* Returns new array object: caller owns the result, must call resp_free() */

resp_object *resp_simple_init(const char *value);
/* Returns new simple string object: caller owns the result, must call
 * resp_free() */

resp_object *resp_error_init(const char *value);
/* Returns new error object: caller owns the result, must call resp_free() */

int resp_array_append_obj(resp_object *destination, resp_object *value);
/* Takes ownership of value */

int resp_array_append_simple(resp_object *destination, const char *str);
/* Copies str: caller may free str after return */

int resp_array_append_bulk(resp_object *destination, const char *str);
/* Copies str: caller may free str after return */

int resp_array_append_int(resp_object *destination, long long i);

#endif
