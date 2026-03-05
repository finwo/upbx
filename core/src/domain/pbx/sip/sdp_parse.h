#ifndef UPBX_SDP_PARSE_H
#define UPBX_SDP_PARSE_H

#include <stddef.h>

#define SDP_MAX_MEDIA 8

typedef struct {
  char ip[64];
  int  port;
  int  is_tcp;
} sdp_media_t;

int sdp_parse_media(const char *body, size_t body_len, sdp_media_t *media, size_t max_media, size_t *n_out);

int sdp_rewrite_addr(const char *body, size_t body_len, const char *new_ip, int new_port, char *out, size_t out_cap);

int sdp_rewrite_addr_with_transport(const char *body, size_t body_len, const char *new_ip, int new_port, int use_tcp,
                                    int direction, char *out, size_t out_cap);

int sdp_rewrite_all_media(const char *body, size_t body_len, const char new_ip[][64], const int *new_port,
                          int num_streams, char *out, size_t out_cap);

#endif
