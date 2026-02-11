/*
 * SDP helpers: parse media info and rewrite addresses.
 *
 * These operate on raw SDP text. No SDP is rebuilt from scratch — only
 * c= IP addresses and m= ports are substituted. Everything else passes
 * through verbatim so endpoint-specific attributes are preserved.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "AppModule/util/sdp_parse.h"

/* Internal helpers */

/* Advance *p past \r\n or \n. */
static void skip_eol(const char **p, const char *end) {
  if (*p < end && **p == '\r') (*p)++;
  if (*p < end && **p == '\n') (*p)++;
}

/* Return pointer to end of current line (before \r or \n). */
static const char *line_end(const char *p, const char *end) {
  while (p < end && *p != '\r' && *p != '\n') p++;
  return p;
}

/* Parse */

int sdp_parse_media(const char *body, size_t body_len,
                    sdp_media_t *media, size_t max_media, size_t *n_out) {
  *n_out = 0;
  const char *p = body, *end = body + body_len;
  char session_ip[64] = {0};

  while (p < end) {
    const char *ls = p;
    const char *le = line_end(p, end);
    size_t ll = (size_t)(le - ls);

    /* Session-level c= (before first m=). */
    if (*n_out == 0 && ll >= 12 && ls[0] == 'c' && ls[1] == '=' &&
        strncmp(ls, "c=IN IP4 ", 9) == 0) {
      size_t iplen = ll - 9;
      if (iplen >= sizeof(session_ip)) iplen = sizeof(session_ip) - 1;
      memcpy(session_ip, ls + 9, iplen);
      session_ip[iplen] = '\0';
    }

    /* m= line: start of a new media section. */
    if (ll >= 4 && ls[0] == 'm' && ls[1] == '=') {
      if (*n_out >= max_media) break;
      sdp_media_t *m = &media[*n_out];
      memset(m, 0, sizeof(*m));

      /* Copy session-level IP as default. */
      if (session_ip[0])
        snprintf(m->ip, sizeof(m->ip), "%s", session_ip);

      /* Parse port: m=<type> <port> ... */
      const char *q = ls + 2;
      while (q < le && *q != ' ') q++;   /* skip media type */
      while (q < le && *q == ' ') q++;    /* skip space */
      if (q < le) m->port = atoi(q);

      (*n_out)++;

      /* Scan following lines for media-level c= (overrides session-level). */
      p = le; skip_eol(&p, end);
      while (p < end) {
        const char *als = p;
        const char *ale = line_end(p, end);
        size_t all = (size_t)(ale - als);
        if (all >= 2 && als[0] == 'm' && als[1] == '=') break; /* next media */
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

/* Rewrite */

int sdp_rewrite_addr(const char *body, size_t body_len,
                     const char *new_ip, int new_port,
                     char *out, size_t out_cap) {
  const char *p = body, *end = body + body_len;
  size_t used = 0;
  int port_rewritten = 0; /* only rewrite first audio m= port */

  /* Macro: append n bytes; fail if overflows. */
  #define APPEND(src, n) do { \
    if (used + (n) > out_cap) return -1; \
    memcpy(out + used, (src), (n)); \
    used += (n); \
  } while (0)

  while (p < end) {
    const char *ls = p;
    const char *le = line_end(p, end);
    size_t ll = (size_t)(le - ls);

    /* Rewrite c=IN IP4 <addr> lines. */
    if (ll >= 12 && ls[0] == 'c' && ls[1] == '=' &&
        strncmp(ls, "c=IN IP4 ", 9) == 0) {
      int n = snprintf(out + used, out_cap - used, "c=IN IP4 %s", new_ip);
      if (n < 0 || used + (size_t)n >= out_cap) return -1;
      used += (size_t)n;
    }
    /* Rewrite port on the first m= line (any media type: audio, video, etc.). */
    else if (!port_rewritten && ll >= 4 && ls[0] == 'm' && ls[1] == '=') {
      const char *q = ls + 2;
      while (q < le && *q != ' ') q++;  /* skip media type */
      if (q < le) {
        q++;  /* skip space after type */
        /* Copy "m=<type> " prefix verbatim. */
        size_t prefix = (size_t)(q - ls);
        APPEND(ls, prefix);
        /* Skip old port digits. */
        while (q < le && *q >= '0' && *q <= '9') q++;
        /* Write new port. */
        int n = snprintf(out + used, out_cap - used, "%d", new_port);
        if (n < 0 || used + (size_t)n >= out_cap) return -1;
        used += (size_t)n;
        /* Append rest of m= line (e.g. " RTP/AVP 8 0 101"). */
        size_t rest = (size_t)(le - q);
        APPEND(q, rest);
        port_rewritten = 1;
      } else {
        /* Malformed m= line (no space); copy verbatim. */
        APPEND(ls, ll);
      }
    }
    /* All other lines: copy verbatim. */
    else {
      APPEND(ls, ll);
    }

    /* Copy the line ending (preserve \r\n or \n). */
    p = le;
    if (p < end && *p == '\r') { APPEND(p, 1); p++; }
    if (p < end && *p == '\n') { APPEND(p, 1); p++; }
  }
  #undef APPEND
  return (int)used;
}
