#ifndef UPBX_DOMAIN_PBX_H
#define UPBX_DOMAIN_PBX_H

#include "common/resp.h"
#include "common/scheduler.h"

void pbx_init(void);
void pbx_shutdown(void);

int sip_transport_udp_pt(int64_t timestamp, struct pt_task *task);
int registration_cleanup_pt(int64_t timestamp, struct pt_task *task);
int udphole_keepalive_pt(int64_t timestamp, struct pt_task *task);
int addrmap_cleanup_pt(int64_t timestamp, struct pt_task *task);
int trunk_register_pt(int64_t timestamp, struct pt_task *task);

#endif
