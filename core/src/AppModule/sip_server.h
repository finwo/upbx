#ifndef UPBX_SIP_SERVER_H
#define UPBX_SIP_SERVER_H

#include "config.h"
#include "common/pt.h"

struct pt_task;

PT_THREAD(daemon_root_pt(struct pt *pt, int64_t timestamp, struct pt_task *task));

#endif
