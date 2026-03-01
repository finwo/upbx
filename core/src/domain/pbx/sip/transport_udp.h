#ifndef __APPMODULE_SIP_TRANSPORT_UDP_H__
#define __APPMODULE_SIP_TRANSPORT_UDP_H__

#include "domain/protothreads.h"
#include "domain/scheduler.h"

struct pt;
struct pt_task;

PT_THREAD(sip_transport_udp_pt(struct pt *pt, int64_t timestamp, struct pt_task *task));

#endif
