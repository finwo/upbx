#ifndef UPBX_PBX_CALL_H
#define UPBX_PBX_CALL_H

#include <stdint.h>
#include <time.h>

typedef struct {
  char  *call_id;
  char  *source_extension;
  char  *destination_extension;
  char  *from_tag;
  char  *to_tag;
  char  *rtp_session_id;
  int   *source_media_ports;
  int    source_media_port_count;
  int   *dest_media_ports;
  int    dest_media_port_count;
  int   *source_rtcp_ports;
  int    source_rtcp_port_count;
  int   *dest_rtcp_ports;
  int    dest_rtcp_port_count;
  char  *source_advertise;
  char  *dest_advertise;
  char  *source_via;
  char  *dest_via;
  time_t answered_at;

  /* trunk call fields */
  int   is_trunk_call;         /* 1 if outbound via trunk, 0 for ext-to-ext */
  char *trunk_name;            /* name of the trunk currently being tried */
  char *trunk_original_dialed; /* immutable original dialed number */
  char *trunk_source_group;    /* source extension's group prefix */
  int   trunk_current_index;   /* index of the trunk currently being tried */
  int   trunk_auth_attempted;  /* 1 if we already retried with auth (prevent loops) */

  /* Original headers from the source extension's INVITE.
   * Used to reconstruct responses in the extension's dialog context. */
  char *orig_from;        /* extension's original From header */
  char *orig_to;          /* extension's original To header */
  int   orig_cseq;        /* extension's original CSeq number */
  char *orig_cseq_method; /* extension's original CSeq method */

  /* Trunk-side dialog headers.  Used to reconstruct ACK/BYE towards the trunk. */
  char *trunk_from;           /* From header used in INVITE to trunk */
  char *trunk_to;             /* To header used in INVITE to trunk */
  int   trunk_cseq;           /* Per-dialog CSeq for trunk side (incremented for each request) */
  char *trunk_remote_contact; /* Contact URI from trunk's 200 OK (ACK target per RFC 3261) */
} pbx_call_t;

void pbx_call_init(void);
void pbx_call_shutdown(void);

pbx_call_t *pbx_call_create(const char *call_id, const char *source_ext, const char *dest_ext, const char *from_tag);
pbx_call_t *pbx_call_find(const char *call_id);
void        pbx_call_delete(const char *call_id);
void        pbx_call_set_media_info(const char *call_id, int *src_ports, int src_count, int *dst_ports, int dst_count,
                                    int *src_rtcp_ports, int src_rtcp_count, int *dst_rtcp_ports, int dst_rtcp_count,
                                    const char *src_adv, const char *dst_adv);
void        pbx_call_set_via(const char *call_id, const char *src_via, const char *dst_via);
void        pbx_call_set_answered(const char *call_id);
void        pbx_call_set_to_tag(const char *call_id, const char *to_tag);

#endif
