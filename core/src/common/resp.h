#ifndef UDPHOLE_RESP_H
#define UDPHOLE_RESP_H

#include <stddef.h>

#define RESPT_SIMPLE  0
#define RESPT_ERROR   1
#define RESPT_BULK    2
#define RESPT_INT      3
#define RESPT_ARRAY    4

typedef struct resp_object resp_object;
struct resp_object {
  int type;
  union {
    char *s;
    long long i;
    struct { resp_object *elem; size_t n; } arr;
  } u;
};

void resp_free(resp_object *o);

resp_object *resp_deep_copy(const resp_object *o);

resp_object *resp_map_get(const resp_object *o, const char *key);

const char *resp_map_get_string(const resp_object *o, const char *key);

void resp_map_set(resp_object *map, const char *key, resp_object *value);

resp_object *resp_read(int fd);

resp_object *resp_read_buf(const char *buf, size_t len);

int resp_encode_array(int argc, const resp_object *const *argv, char **out_buf, size_t *out_len);

int resp_serialize(const resp_object *o, char **out_buf, size_t *out_len);

resp_object *resp_array_init(void);

int resp_array_append_obj(resp_object *destination, resp_object *value);

int resp_array_append_simple(resp_object *destination, const char *str);
int resp_array_append_bulk(resp_object *destination, const char *str);
int resp_array_append_int(resp_object *destination, long long i);

#endif