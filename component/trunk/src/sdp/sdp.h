#ifndef TRK_SDP_H
#define TRK_SDP_H

#include <stddef.h>

#define MAX_CODEC_TAGS 16

struct codec_tag {
    int  stream_id;       // RTP payload type, -1 if unknown
    char media_type[16];  // "audio", "video", etc.
    char codec[64];       // opaque: "PCMU/8000", "telephone-event/8000"
};

struct sdp_info {
    char *c_addr;     // connection address from c= line
    int   m_port;     // port from first m= line

    /* codec tags from a=rtpmap lines */
    struct codec_tag codecs[MAX_CODEC_TAGS];
    int codec_count;
    char media_type[16]; // from m= line ("audio", "video")
};

struct sdp_info *sdp_parse(const char *body, int len);
void sdp_free(struct sdp_info *info);

// Return malloc'd copy of body with c= IP and m= port replaced
char *sdp_rewrite(const char *body, int len, const char *new_ip, int new_port, int *out_len);

// Build SDP body from codec tags. Returns malloc'd string.
// listen_ip: the local IP to advertise in c=/o= lines (NULL for default 0.0.0.0)
// addr_family: "IP4" or "IP6"
char *sdp_build_from_codecs(int rtp_port, const char *listen_ip,
                            const char *addr_family,
                            struct codec_tag *tags, int tag_count);

// Build codec tags string from codec array. Returns malloc'd string.
char *codec_tags_to_string(struct codec_tag *tags, int tag_count);

// Parse flexible codec tags string into tag array. Returns tag count.
int codec_tags_from_string(const char *str, struct codec_tag *tags, int max_tags);

#endif
