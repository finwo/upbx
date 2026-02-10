#ifndef UPBX_SDP_PARSE_H
#define UPBX_SDP_PARSE_H

#include <stddef.h>

/*
 * SDP helpers: parse to extract IP/port, and rewrite addresses in-place.
 * Only two operations:
 *   1. Parse: extract remote IP and media port(s) from an SDP body.
 *   2. Rewrite: copy SDP body, replacing only c= IP and m= port.
 */

#define SDP_MAX_MEDIA 8

/* Parsed media entry: IP address and port extracted from one m= section. */
typedef struct {
  char   ip[64];   /* from c= line (session-level or media-level) */
  int    port;     /* from m= line */
} sdp_media_t;

/* Parse SDP body; extract IP and port for each media stream.
 * Fills media[0..*n_out-1]. Returns 0 on success, -1 if no media found. */
int sdp_parse_media(const char *body, size_t body_len,
                    sdp_media_t *media, size_t max_media, size_t *n_out);

/* Rewrite SDP body: copy verbatim, replacing only:
 *   - c=IN IP4 <old> → c=IN IP4 <new_ip>  (all c= lines)
 *   - m=<type> <old_port> → m=<type> <new_port>  (first m= line)
 * Everything else (o=, s=, t=, a= lines, codec lists) passes through unchanged.
 * Writes to out (up to out_cap bytes). Returns number of bytes written, or -1 on error. */
int sdp_rewrite_addr(const char *body, size_t body_len,
                     const char *new_ip, int new_port,
                     char *out, size_t out_cap);

#endif
