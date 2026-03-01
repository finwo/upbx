#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "domain/pbx/sip/sdp_parse.h"

static void skip_eol(const char **p, const char *end) {
  if (*p < end && **p == '\r') (*p)++;
  if (*p < end && **p == '\n') (*p)++;
}

static const char *line_end(const char *p, const char *end) {
  while (p < end && *p != '\r' && *p != '\n') p++;
  return p;
}

int sdp_parse_media(const char *body, size_t body_len,
                    sdp_media_t *media, size_t max_media, size_t *n_out) {
  *n_out = 0;
  const char *p = body, *end = body + body_len;
  char session_ip[64] = {0};

  while (p < end) {
    const char *ls = p;
    const char *le = line_end(p, end);
    size_t ll = (size_t)(le - ls);

    if (*n_out == 0 && ll >= 12 && ls[0] == 'c' && ls[1] == '=' &&
        strncmp(ls, "c=IN IP4 ", 9) == 0) {
      size_t iplen = ll - 9;
      if (iplen >= sizeof(session_ip)) iplen = sizeof(session_ip) - 1;
      memcpy(session_ip, ls + 9, iplen);
      session_ip[iplen] = '\0';
    }

    if (ll >= 4 && ls[0] == 'm' && ls[1] == '=') {
      if (*n_out >= max_media) break;
      sdp_media_t *m = &media[*n_out];
      memset(m, 0, sizeof(*m));

      if (session_ip[0])
        snprintf(m->ip, sizeof(m->ip), "%s", session_ip);

      const char *q = ls + 2;
      while (q < le && *q != ' ') q++;
      while (q < le && *q == ' ') q++;
      if (q < le) m->port = atoi(q);

      const char *proto_start = q;
      while (q < le && *q != ' ' && *q != '\r' && *q != '\n') q++;
      size_t proto_len = (size_t)(q - proto_start);
      if (proto_len >= 11 && strncmp(proto_start + proto_len - 3, "TCP", 3) == 0) {
        m->is_tcp = 1;
      }

      (*n_out)++;

      p = le; skip_eol(&p, end);
      while (p < end) {
        const char *als = p;
        const char *ale = line_end(p, end);
        size_t all = (size_t)(ale - als);
        if (all >= 2 && als[0] == 'm' && als[1] == '=') break;
        if (all >= 12 && strncmp(als, "c=IN IP4 ", 9) == 0) {
          size_t iplen = all - 9;
          if (iplen >= sizeof(m->ip)) iplen = sizeof(m->ip) - 1;
          memcpy(m->ip, als + 9, iplen);
          m->ip[iplen] = '\0';
        }
        p = ale; skip_eol(&p, end);
      }
      continue;
    }
    p = le; skip_eol(&p, end);
  }
  return (*n_out > 0) ? 0 : -1;
}

int sdp_rewrite_addr(const char *body, size_t body_len,
                     const char *new_ip, int new_port,
                     char *out, size_t out_cap) {
  return sdp_rewrite_addr_with_transport(body, body_len, new_ip, new_port, 0, 0, out, out_cap);
}

int sdp_rewrite_addr_with_transport(const char *body, size_t body_len,
                                    const char *new_ip, int new_port, int use_tcp,
                                    int direction,
                                    char *out, size_t out_cap) {
  const char *p = body, *end = body + body_len;
  char *o = out;
  size_t remain = out_cap;

  while (p < end) {
    const char *ls = p;
    const char *le = line_end(p, end);
    size_t ll = (size_t)(le - ls);

    if (ll >= 9 && strncmp(ls, "c=IN IP4 ", 9) == 0) {
      size_t need = 9 + strlen(new_ip) + 2;
      if (need > remain) return -1;
      memcpy(o, "c=IN IP4 ", 9);
      memcpy(o + 9, new_ip, strlen(new_ip));
      o += need - 2;
      *o++ = '\r';
      *o++ = '\n';
      remain -= need;
    } else if (ll >= 8 && ls[0] == 'm' && ls[1] == '=' &&
               strncmp(ls + 2, "audio ", 6) == 0) {
      const char *q = ls + 8;
      while (q < le && *q >= '0' && *q <= '9') q++;
      size_t old_port_len = (size_t)(q - (ls + 8));
      char port_buf[16];
      snprintf(port_buf, sizeof(port_buf), "%d", new_port);
      size_t new_port_len = strlen(port_buf);

      size_t need = 8 + new_port_len + (size_t)(le - q) + 2;
      if (need > remain) return -1;

      memcpy(o, "m=audio ", 8);
      memcpy(o + 8, port_buf, new_port_len);
      memcpy(o + 8 + new_port_len, q, (size_t)(le - q));
      o += need - 2;
      *o++ = '\r';
      *o++ = '\n';
      remain -= need;
    } else {
      size_t need = ll + 2;
      if (need > remain) return -1;
      memcpy(o, ls, ll);
      o += ll;
      *o++ = '\r';
      *o++ = '\n';
      remain -= need;
    }

    p = le; skip_eol(&p, end);
  }

  if (direction != 0 && out_cap >= 24 + remain) {
    const char *dir_str = "";
    switch (direction) {
      case 1: dir_str = "a=sendonly\r\n"; break;
      case 2: dir_str = "a=recvonly\r\n"; break;
      case 3: dir_str = "a=sendrecv\r\n"; break;
    }
    size_t dlen = strlen(dir_str);
    if (dlen < remain) {
      memcpy(o, dir_str, dlen);
      o += dlen;
    }
  }

  *o = '\0';
  return (int)(o - out);
}
