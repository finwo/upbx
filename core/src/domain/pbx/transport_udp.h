#ifndef UPBX_PBX_TRANSPORT_UDP_H
#define UPBX_PBX_TRANSPORT_UDP_H

#include "common/scheduler.h"

int sip_transport_udp_pt(int64_t timestamp, struct pt_task *task);

/* Get the first SIP UDP listening socket fd.
 * Returns -1 if not yet initialized. */
int pbx_transport_get_sip_fd(void);

#endif
