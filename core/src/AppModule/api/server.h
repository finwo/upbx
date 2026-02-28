#ifndef __APPMODULE_API_SERVER_H__
#define __APPMODULE_API_SERVER_H__

#include <stdint.h>

#include "SchedulerModule/scheduler.h"

PT_THREAD(api_server_pt(struct pt *pt, int64_t timestamp, struct pt_task *task));

#endif // __APPMODULE_API_SERVER_H__
