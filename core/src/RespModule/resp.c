/*
 * RESP encoding and decoding implementation.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "RespModule/resp.h"

#define MAX_BULK_LEN    (256 * 1024)
#define LINE_BUF        4096

static void resp_free_internal(resp_object *o);

static int resp_read_byte(int fd) {
  unsigned char c;
  if (read(fd, &c, 1) != 1)
    return -1;
  return (int)c;
}

static int resp_read_line(int fd, char *buf, size_t buf_size) {
  size_t i = 0;
  int prev = -1;
  while (i + 1 < buf_size) {
    int b = resp_read_byte(fd);
    if (b < 0) return -1;
    if (prev == '\r' && b == '\n') {
      buf[i - 1] = '\0';
      return 0;
    }
    prev = b;
    buf[i++] = (char)b;
  }
  return -1;
}

resp_object *resp_read(int fd) {
  int type_c = resp_read_byte(fd);
  if (type_c < 0) return NULL;
  resp_object *o = calloc(1, sizeof(resp_object));
  if (!o) return NULL;
  char line[LINE_BUF];
  switch ((char)type_c) {
    case '+':
      o->type = RESPT_SIMPLE;
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      o->u.s = strdup(line);
      break;
    case '-':
      o->type = RESPT_ERROR;
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      o->u.s = strdup(line);
      break;
    case ':': {
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      o->type = RESPT_INT;
      o->u.i = (long long)strtoll(line, NULL, 10);
      break;
    }
    case '$': {
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      long len = strtol(line, NULL, 10);
      if (len < 0 || len > (long)MAX_BULK_LEN) { free(o); return NULL; }
      o->type = RESPT_BULK;
      if (len == 0) {
        o->u.s = strdup("");
        if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o->u.s); free(o); return NULL; }
      } else {
        o->u.s = malloc((size_t)len + 1);
        if (!o->u.s) { free(o); return NULL; }
        if (read(fd, o->u.s, (size_t)len) != (ssize_t)len) { free(o->u.s); free(o); return NULL; }
        o->u.s[len] = '\0';
        if (resp_read_byte(fd) != '\r' || resp_read_byte(fd) != '\n') { free(o->u.s); free(o); return NULL; }
      }
      break;
    }
    case '*': {
      if (resp_read_line(fd, line, sizeof(line)) != 0) { free(o); return NULL; }
      long n = strtol(line, NULL, 10);
      if (n < 0 || n > 65536) { free(o); return NULL; }
      o->type = RESPT_ARRAY;
      o->u.arr.n = (size_t)n;
      o->u.arr.elem = n ? calloc((size_t)n, sizeof(resp_object)) : NULL;
      if (n && !o->u.arr.elem) { free(o); return NULL; }
      for (size_t i = 0; i < (size_t)n; i++) {
        resp_object *sub = resp_read(fd);
        if (!sub) {
          for (size_t j = 0; j < i; j++) resp_free_internal(&o->u.arr.elem[j]);
          free(o->u.arr.elem);
          free(o);
          return NULL;
        }
        o->u.arr.elem[i] = *sub;
        free(sub);
      }
      break;
    }
    default:
      free(o);
      return NULL;
  }
  return o;
}

static void resp_free_internal(resp_object *o) {
  if (!o) return;
  if (o->type == RESPT_SIMPLE || o->type == RESPT_ERROR || o->type == RESPT_BULK) {
    free(o->u.s);
  } else if (o->type == RESPT_ARRAY) {
    for (size_t i = 0; i < o->u.arr.n; i++)
      resp_free_internal(&o->u.arr.elem[i]);
    free(o->u.arr.elem);
  }
}

void resp_free(resp_object *o) {
  resp_free_internal(o);
}

resp_object *resp_deep_copy(const resp_object *o) {
  if (!o) return NULL;
  resp_object *c = (resp_object *)calloc(1, sizeof(resp_object));
  if (!c) return NULL;
  c->type = o->type;
  if (o->type == RESPT_SIMPLE || o->type == RESPT_ERROR || o->type == RESPT_BULK) {
    c->u.s = o->u.s ? strdup(o->u.s) : NULL;
    if (o->u.s && !c->u.s) { free(c); return NULL; }
    return c;
  }
  if (o->type == RESPT_INT) {
    c->u.i = o->u.i;
    return c;
  }
  if (o->type == RESPT_ARRAY) {
    c->u.arr.n = o->u.arr.n;
    c->u.arr.elem = o->u.arr.n ? (resp_object *)calloc(o->u.arr.n, sizeof(resp_object)) : NULL;
    if (o->u.arr.n && !c->u.arr.elem) { free(c); return NULL; }
    for (size_t i = 0; i < o->u.arr.n; i++) {
      resp_object *sub = resp_deep_copy(&o->u.arr.elem[i]);
      if (!sub) {
        for (size_t j = 0; j < i; j++) resp_free_internal(&c->u.arr.elem[j]);
        free(c->u.arr.elem);
        free(c);
        return NULL;
      }
      c->u.arr.elem[i] = *sub;
      free(sub);
    }
    return c;
  }
  free(c);
  return NULL;
}

resp_object *resp_map_get(const resp_object *o, const char *key) {
  if (!o || !key || o->type != RESPT_ARRAY) return NULL;
  size_t n = o->u.arr.n;
  if (n & 1) return NULL;
  for (size_t i = 0; i < n; i += 2) {
    const resp_object *k = &o->u.arr.elem[i];
    const char *s = (k->type == RESPT_BULK || k->type == RESPT_SIMPLE) ? k->u.s : NULL;
    if (s && strcmp(s, key) == 0 && i + 1 < n)
      return (resp_object *)&o->u.arr.elem[i + 1];
  }
  return NULL;
}

const char *resp_map_get_string(const resp_object *o, const char *key) {
  resp_object *val = resp_map_get(o, key);
  if (!val) return NULL;
  if (val->type == RESPT_BULK || val->type == RESPT_SIMPLE)
    return val->u.s;
  return NULL;
}

/* Append one RESP-encoded object to buf; realloc as needed. Returns 0 on success. */
static int resp_append_object(char **buf, size_t *cap, size_t *len, const resp_object *o) {
  if (!o) return -1;
  size_t need = *len + 256;
  if (o->type == RESPT_BULK || o->type == RESPT_SIMPLE || o->type == RESPT_ERROR) {
    size_t slen = o->u.s ? strlen(o->u.s) : 0;
    need = *len + 32 + slen + 2;
  } else if (o->type == RESPT_ARRAY) {
    need = *len + 32;
    for (size_t i = 0; i < o->u.arr.n; i++)
      need += 64;
  }
  if (need > *cap) {
    size_t newcap = need + 4096;
    char *n = realloc(*buf, newcap);
    if (!n) return -1;
    *buf = n;
    *cap = newcap;
  }
  switch (o->type) {
    case RESPT_SIMPLE: {
      const char *s = o->u.s ? o->u.s : "";
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "+%s\r\n", s);
      break;
    }
    case RESPT_ERROR: {
      const char *s = o->u.s ? o->u.s : "";
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "-%s\r\n", s);
      break;
    }
    case RESPT_INT:
      *len += (size_t)snprintf(*buf + *len, *cap - *len, ":%lld\r\n", (long long)o->u.i);
      break;
    case RESPT_BULK: {
      const char *s = o->u.s ? o->u.s : "";
      size_t slen = strlen(s);
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "$%zu\r\n%s\r\n", slen, s);
      break;
    }
    case RESPT_ARRAY: {
      size_t n = o->u.arr.n;
      *len += (size_t)snprintf(*buf + *len, *cap - *len, "*%zu\r\n", n);
      for (size_t i = 0; i < n; i++) {
        if (resp_append_object(buf, cap, len, &o->u.arr.elem[i]) != 0)
          return -1;
      }
      break;
    }
    default:
      return -1;
  }
  return 0;
}

int resp_encode_array(int argc, const resp_object *const *argv, char **out_buf, size_t *out_len) {
  size_t cap = 64;
  size_t len = 0;
  char *buf = malloc(cap);
  if (!buf) return -1;
  len += (size_t)snprintf(buf + len, cap - len, "*%d\r\n", argc);
  if (len >= cap) { free(buf); return -1; }
  for (int i = 0; i < argc; i++) {
    if (resp_append_object(&buf, &cap, &len, argv[i]) != 0) {
      free(buf);
      return -1;
    }
  }
  *out_buf = buf;
  *out_len = len;
  return 0;
}

resp_object *resp_array_init(void) {
  resp_object *o = calloc(1, sizeof(resp_object));
  if (!o) return NULL;
  o->type = RESPT_ARRAY;
  o->u.arr.n = 0;
  o->u.arr.elem = NULL;
  return o;
}

int resp_array_append_obj(resp_object *destination, resp_object *value) {
  if (!destination || destination->type != RESPT_ARRAY || !value) return -1;
  size_t n = destination->u.arr.n;
  resp_object *new_elem = realloc(destination->u.arr.elem, (n + 1) * sizeof(resp_object));
  if (!new_elem) return -1;
  destination->u.arr.elem = new_elem;
  destination->u.arr.elem[n] = *value;
  destination->u.arr.n++;
  free(value);
  return 0;
}

int resp_array_append_simple(resp_object *destination, const char *str) {
  resp_object *o = calloc(1, sizeof(resp_object));
  if (!o) return -1;
  o->type = RESPT_SIMPLE;
  o->u.s = strdup(str ? str : "");
  if (!o->u.s) { free(o); return -1; }
  if (resp_array_append_obj(destination, o) != 0) { free(o->u.s); free(o); return -1; }
  return 0;
}

int resp_array_append_bulk(resp_object *destination, const char *str) {
  resp_object *o = calloc(1, sizeof(resp_object));
  if (!o) return -1;
  o->type = RESPT_BULK;
  o->u.s = strdup(str ? str : "");
  if (!o->u.s) { free(o); return -1; }
  if (resp_array_append_obj(destination, o) != 0) { free(o->u.s); free(o); return -1; }
  return 0;
}

int resp_array_append_int(resp_object *destination, long long i) {
  resp_object *o = malloc(sizeof(resp_object));
  if (!o) return -1;
  o->type = RESPT_INT;
  o->u.i = i;
  return resp_array_append_obj(destination, o);
}
