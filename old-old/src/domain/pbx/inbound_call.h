#ifndef UPBX_PBX_INBOUND_CALL_H
#define UPBX_PBX_INBOUND_CALL_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  INBOUND_LEG_PENDING,
  INBOUND_LEG_RINGING,
  INBOUND_LEG_ANSWERED,
  INBOUND_LEG_CANCELLED,
  INBOUND_LEG_FAILED
} inbound_leg_state_t;

typedef struct {
  char                extension[32];
  inbound_leg_state_t state;
  int                 final_status;
  int                *media_ports;
  int                 media_port_count;
  int                *rtcp_ports;
  int                 rtcp_port_count;
  char               *advertise_addr;
  char               *from_tag;
  char               *to_tag;
  char               *leg_to;
  int                 cseq;
  char               *branch;
} inbound_leg_t;

typedef struct {
  char   *trunk_call_id;
  char   *trunk_name;

  char    trunk_socket_type[16];
  int    *trunk_media_ports;
  int     trunk_media_port_count;
  int    *trunk_rtcp_ports;
  int     trunk_rtcp_port_count;
  char   *trunk_advertise_addr;
  char   *trunk_remote_ip;
  int    *trunk_remote_media_ports;
  int     trunk_remote_media_port_count;

  char   *trunk_from;
  char   *trunk_to;
  char   *trunk_to_tag;
  char   *trunk_via;
  int     trunk_cseq;
  char   *trunk_contact;
  char   *trunk_sdp;

  char   *rtp_session_id;

  char   *did;

  inbound_leg_t **legs;
  size_t          leg_count;
  size_t          leg_capacity;

  int             answered;
  char           *answered_extension;

  int             first_180_sent;

  int             leg_cseq_counter;
} inbound_call_t;

void            inbound_call_init(void);
void            inbound_call_shutdown(void);

inbound_call_t *inbound_call_create(const char *call_id, const char *trunk_name);
inbound_call_t *inbound_call_find(const char *call_id);
void            inbound_call_delete(const char *call_id);

inbound_leg_t  *inbound_call_add_leg(inbound_call_t *call, const char *extension);
inbound_leg_t  *inbound_call_find_leg(inbound_call_t *call, const char *extension);
void            inbound_call_destroy_leg_sockets(inbound_call_t *call, inbound_leg_t *leg);

int             inbound_call_all_legs_terminated(inbound_call_t *call);
int             inbound_call_select_final_status(inbound_call_t *call);

void            inbound_call_free_leg(inbound_leg_t *leg);

#endif
