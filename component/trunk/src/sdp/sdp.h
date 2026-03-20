#ifndef TRK_SDP_H
#define TRK_SDP_H

#include <stddef.h>

struct sdp_info {
    char *c_addr;     // connection address from c= line
    int   m_port;     // port from first m= line
};

struct sdp_info *sdp_parse(const char *body, int len);
void sdp_free(struct sdp_info *info);

// Return malloc'd copy of body with c= IP and m= port replaced
char *sdp_rewrite(const char *body, int len, const char *new_ip, int new_port, int *out_len);

#endif
