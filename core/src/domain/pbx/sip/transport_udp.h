#ifndef __APPMODULE_SIP_TRANSPORT_UDP_H__
#define __APPMODULE_SIP_TRANSPORT_UDP_H__

#include "common/scheduler.h"

struct pt_task;

int sip_transport_udp_pt(int64_t timestamp, struct pt_task *task);

#endif
