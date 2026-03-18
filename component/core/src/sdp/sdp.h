#ifndef SDP_H
#define SDP_H

#include <stddef.h>

char *sdp_replace_ip_port(const char *sdp, size_t sdp_len, const char *ip, int port, size_t *out_len);

char *sdp_get_ip_port(const char *sdp, size_t sdp_len, char *ip_out, int *port_out);

#endif // SDP_H
