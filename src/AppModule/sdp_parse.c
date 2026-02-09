/*
 * SDP (Session Description Protocol) parser and builder.
 * Used in SIP bodies to describe RTP sessions; format is independent of SIP.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "AppModule/sdp_parse.h"

int sdp_parse_all_media(const char *body, size_t body_len, sdp_media_block_t *blocks, size_t max_blocks, size_t *n_out) {
  *n_out = 0;
  const char *p = body, *end = body + body_len;
  const char *session_c = NULL;
  size_t session_c_len = 0;
  while (p < end && *n_out < max_blocks) {
    const char *line_start = p;
    while (p < end && *p != '\r' && *p != '\n') p++;
    size_t line_len = (size_t)(p - line_start);
    if (line_len >= 2 && line_start[0] == 'c' && line_start[1] == '=') {
      if (!session_c && line_len >= 12 && strncmp(line_start, "c=IN IP4 ", 9) == 0) {
        session_c = line_start + 9;
        session_c_len = line_len - 9;
        while (session_c_len > 0 && (session_c[session_c_len - 1] == '\r' || session_c[session_c_len - 1] == '\n'))
          session_c_len--;
      }
    } else if (line_len >= 2 && line_start[0] == 'm' && line_start[1] == '=') {
      sdp_media_block_t *out = &blocks[*n_out];
      memset(out, 0, sizeof(*out));
      const char *m_rest = line_start + 2;
      while (m_rest < line_start + line_len && (*m_rest == ' ' || *m_rest == '\t')) m_rest++;
      const char *media_end = m_rest;
      while (media_end < line_start + line_len && *media_end != ' ' && *media_end != '\t') media_end++;
      out->m_media = m_rest;
      out->m_media_len = (size_t)(media_end - m_rest);
      m_rest = media_end;
      while (m_rest < line_start + line_len && (*m_rest == ' ' || *m_rest == '\t')) m_rest++;
      const char *port_start = m_rest;
      while (port_start < line_start + line_len && *port_start >= '0' && *port_start <= '9') port_start++;
      if (port_start > m_rest) {
        out->m_port = atoi(m_rest);
        out->m_rest = port_start;
        while (out->m_rest < line_start + line_len && (*out->m_rest == ' ' || *out->m_rest == '\t')) out->m_rest++;
        out->m_rest_len = (size_t)((line_start + line_len) - out->m_rest);
      }
      if (session_c) {
        out->c_addr = session_c;
        out->c_addr_len = session_c_len;
      }
      if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
      else if (p < end) p++;
      size_t a_used = 0, a_cap = 2048;
      out->a_block = malloc(a_cap);
      if (!out->a_block) goto fail;
      while (p < end) {
        const char *a_start = p;
        while (p < end && *p != '\r' && *p != '\n') p++;
        if (a_start == p) break;
        size_t a_len = (size_t)(p - a_start);
        if (a_len >= 2 && a_start[0] == 'a' && a_start[1] == '=') {
          if (a_used + a_len + 2 <= a_cap) {
            memcpy(out->a_block + a_used, a_start, a_len);
            out->a_block[a_used + a_len] = '\r';
            out->a_block[a_used + a_len + 1] = '\n';
            a_used += a_len + 2;
          }
        } else if (a_len >= 2 && a_start[0] == 'm' && a_start[1] == '=')
          break;
        if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
        else if (p < end) p++;
      }
      out->a_block_len = a_used;
      (*n_out)++;
    }
    if (p + 1 < end && p[0] == '\r' && p[1] == '\n') p += 2;
    else if (p < end) p++;
  }
  return (*n_out) > 0 ? 0 : -1;
fail:
  for (size_t i = 0; i < *n_out; i++)
    free(blocks[i].a_block);
  *n_out = 0;
  return -1;
}

void sdp_media_blocks_free(sdp_media_block_t *blocks, size_t n) {
  for (size_t i = 0; i < n; i++)
    free(blocks[i].a_block);
}

int sdp_build(const char *session_addr, const sdp_media_block_t *blocks, size_t n_blocks,
  const int *port_per_media, int skip_media_with_port_le_zero,
  char **out_body, size_t *out_len) {
  if (!session_addr || !out_body || !out_len) return -1;
  size_t cap = 256;
  for (size_t i = 0; i < n_blocks; i++)
    cap += 128 + blocks[i].m_rest_len + (blocks[i].a_block_len ? blocks[i].a_block_len : 0);
  char *out = malloc(cap);
  if (!out) return -1;
  size_t used = 0;
  unsigned long o_sess = (unsigned long)time(NULL);
  int n = snprintf(out + used, cap - used, "v=0\r\no=- %lu %lu IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n",
    o_sess, o_sess, session_addr, session_addr);
  if (n <= 0 || (size_t)n >= cap) {
    free(out);
    return -1;
  }
  used += (size_t)n;
  int any_written = 0;
  for (size_t i = 0; i < n_blocks; i++) {
    int port = port_per_media ? port_per_media[i] : blocks[i].m_port;
    if (skip_media_with_port_le_zero && port <= 0) continue;
    if (port < 0) port = 0;
    const sdp_media_block_t *b = &blocks[i];
    n = snprintf(out + used, cap - used, "m=%.*s %d %.*s\r\n",
      (int)b->m_media_len, b->m_media, port, (int)b->m_rest_len, b->m_rest);
    if (n <= 0 || (size_t)(used + n) >= cap) {
      free(out);
      return -1;
    }
    used += (size_t)n;
    if (b->a_block && b->a_block_len && used + b->a_block_len <= cap) {
      memcpy(out + used, b->a_block, b->a_block_len);
      used += b->a_block_len;
    }
    any_written = 1;
  }
  if (!any_written && skip_media_with_port_le_zero) {
    free(out);
    return -1;
  }
  *out_body = out;
  *out_len = used;
  return 0;
}
