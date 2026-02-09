#ifndef UPBX_SDP_PARSE_H
#define UPBX_SDP_PARSE_H

#include <stddef.h>

/*
 * SDP (Session Description Protocol) parser and builder.
 * SDP is independent of SIP; we use it in SIP bodies to describe RTP sessions.
 * All parsing and wire formatting of SDP lives here.
 */

#define SDP_MAX_MEDIA 16

/* Parsed media block (m= and following a= lines). c_addr/m_media/m_rest point into the original body; body must stay valid. a_block is malloc'd, freed by sdp_media_blocks_free. */
typedef struct {
  const char *c_addr;      /* session-level c= address (e.g. "192.168.1.1") or NULL */
  size_t c_addr_len;
  const char *m_media;      /* media type (e.g. "audio") */
  size_t m_media_len;
  int m_port;              /* port from m= line */
  const char *m_rest;      /* from after port to EOL: " RTP/AVP 3 101" */
  size_t m_rest_len;
  char *a_block;           /* concatenated a= lines after this m= until next m= (malloc'd) */
  size_t a_block_len;
} sdp_media_block_t;

/* Parse SDP body; fill blocks[0..*n_out-1]. Caller must call sdp_media_blocks_free. Pointers in blocks refer into body. Returns 0 on success, -1 on error. */
int sdp_parse_all_media(const char *body, size_t body_len, sdp_media_block_t *blocks, size_t max_blocks, size_t *n_out);

/* Free a_block in blocks[0..n-1]. */
void sdp_media_blocks_free(sdp_media_block_t *blocks, size_t n);

/* Build SDP body: v=0, o=-, s=-, c=IN IP4 session_addr, t=0 0, then one m= per block (with optional a= block).
 * port_per_media[i] = port to use for blocks[i] (or 0).
 * skip_media_with_port_le_zero: if 1, omit m= line when port_per_media[i] <= 0; if 0, emit all m= (port may be 0).
 * Caller frees *out_body. Returns 0 on success, -1 on error. */
int sdp_build(const char *session_addr, const sdp_media_block_t *blocks, size_t n_blocks,
  const int *port_per_media, int skip_media_with_port_le_zero,
  char **out_body, size_t *out_len);

#endif
