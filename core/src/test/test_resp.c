/*
 * RESP encoding and decoding tests using finwo/assert.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "finwo/assert.h"
#include "RespModule/resp.h"

/* Write encoded buf to pipe, read back one RESP value. Caller resp_frees result. */
static resp_object *round_trip(const char *buf, size_t len) {
  int fd[2];
  if (pipe(fd) != 0) return NULL;
  ssize_t n = write(fd[1], buf, len);
  close(fd[1]);
  if (n != (ssize_t)len) { close(fd[0]); return NULL; }
  resp_object *o = resp_read(fd[0]);
  close(fd[0]);
  return o;
}

void test_resp_encode_decode_bulk(void) {
  resp_object bulk = { .type = RESPT_BULK, .u = { .s = strdup("hello") } };
  const resp_object *av[] = { &bulk };
  char *buf = NULL;
  size_t len = 0;
  ASSERT_EQUALS(0, resp_encode_array(1, av, &buf, &len));
  ASSERT("encoded", buf != NULL && len > 0);
  resp_object *dec = round_trip(buf, len);
  ASSERT("decode non-NULL", dec != NULL);
  ASSERT_EQUALS(RESPT_ARRAY, dec->type);
  ASSERT_EQUALS(1, (int)dec->u.arr.n);
  ASSERT_EQUALS(RESPT_BULK, dec->u.arr.elem[0].type);
  ASSERT_STRING_EQUALS("hello", dec->u.arr.elem[0].u.s);
  resp_free(dec);
  free(buf);
  free(bulk.u.s);
}

void test_resp_encode_decode_int(void) {
  resp_object iobj = { .type = RESPT_INT, .u = { .i = -42 } };
  const resp_object *av[] = { &iobj };
  char *buf = NULL;
  size_t len = 0;
  ASSERT_EQUALS(0, resp_encode_array(1, av, &buf, &len));
  resp_object *dec = round_trip(buf, len);
  ASSERT("decode non-NULL", dec != NULL);
  ASSERT_EQUALS(RESPT_ARRAY, dec->type);
  ASSERT_EQUALS(1, (int)dec->u.arr.n);
  ASSERT_EQUALS(RESPT_INT, dec->u.arr.elem[0].type);
  ASSERT_EQUALS(-42, (int)dec->u.arr.elem[0].u.i);
  resp_free(dec);
  free(buf);
}

void test_resp_encode_decode_array_of_strings(void) {
  resp_object k = { .type = RESPT_BULK, .u = { .s = strdup("key") } };
  resp_object v = { .type = RESPT_BULK, .u = { .s = strdup("value") } };
  const resp_object *av[] = { &k, &v };
  char *buf = NULL;
  size_t len = 0;
  ASSERT_EQUALS(0, resp_encode_array(2, av, &buf, &len));
  resp_object *dec = round_trip(buf, len);
  ASSERT("decode non-NULL", dec != NULL);
  ASSERT_EQUALS(RESPT_ARRAY, dec->type);
  ASSERT_EQUALS(2, (int)dec->u.arr.n);
  ASSERT_EQUALS(RESPT_BULK, dec->u.arr.elem[0].type);
  ASSERT_EQUALS(RESPT_BULK, dec->u.arr.elem[1].type);
  ASSERT_STRING_EQUALS("key", dec->u.arr.elem[0].u.s);
  ASSERT_STRING_EQUALS("value", dec->u.arr.elem[1].u.s);
  resp_free(dec);
  free(buf);
  free(k.u.s);
  free(v.u.s);
}

void test_resp_map_get_string(void) {
  resp_object k1 = { .type = RESPT_BULK, .u = { .s = strdup("a") } };
  resp_object v1 = { .type = RESPT_BULK, .u = { .s = strdup("1") } };
  resp_object k2 = { .type = RESPT_BULK, .u = { .s = strdup("b") } };
  resp_object v2 = { .type = RESPT_BULK, .u = { .s = strdup("2") } };
  resp_object *map = calloc(1, sizeof(resp_object));
  ASSERT("map alloc", map != NULL);
  map->type = RESPT_ARRAY;
  map->u.arr.n = 4;
  map->u.arr.elem = calloc(4, sizeof(resp_object));
  map->u.arr.elem[0] = k1;
  map->u.arr.elem[1] = v1;
  map->u.arr.elem[2] = k2;
  map->u.arr.elem[3] = v2;
  ASSERT_STRING_EQUALS("1", resp_map_get_string(map, "a"));
  ASSERT_STRING_EQUALS("2", resp_map_get_string(map, "b"));
  ASSERT("missing key returns NULL", resp_map_get_string(map, "c") == NULL);
  resp_free(map);
}

void test_resp_map_get_missing_key(void) {
  resp_object *map = resp_array_init();
  ASSERT("map alloc", map != NULL);
  ASSERT("missing key NULL", resp_map_get_string(map, "x") == NULL);
  ASSERT("resp_map_get NULL", resp_map_get(map, "x") == NULL);
  resp_free(map);
}

void test_resp_read_invalid_returns_null(void) {
  int fd[2];
  ASSERT_EQUALS(0, pipe(fd));
  if (write(fd[1], "X\r\n", 3) != 3) { close(fd[0]); close(fd[1]); return; }
  close(fd[1]);
  resp_object *o = resp_read(fd[0]);
  close(fd[0]);
  ASSERT("invalid type byte returns NULL", o == NULL);
}

int main(void) {
  RUN(test_resp_encode_decode_bulk);
  RUN(test_resp_encode_decode_int);
  RUN(test_resp_encode_decode_array_of_strings);
  RUN(test_resp_map_get_string);
  RUN(test_resp_map_get_missing_key);
  RUN(test_resp_read_invalid_returns_null);
  return TEST_REPORT();
}
