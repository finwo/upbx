#ifndef __APPMODULE_RTP_SERVER_H__
#define __APPMODULE_RTP_SERVER_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#include "SchedulerModule/protothreads.h"

struct pt;
struct pt_task;

PT_THREAD(rtpproxy_server_pt(struct pt *pt, int64_t timestamp, struct pt_task *task));

#endif
