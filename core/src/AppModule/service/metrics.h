/*
 * Metrics module: registers metrics.* commands with the API server,
 * maintains call load-average state.
 */
#ifndef UPBX_SERVICE_METRICS_H
#define UPBX_SERVICE_METRICS_H

#include <time.h>

#include "common/pt.h"

/* Register metrics commands with the API server and initialise state.
 * Call after api_start() but before the main loop. */
void metrics_init(void);

/* Protothread: update load-average EMAs every second. Schedule from main loop with loop_timestamp. */
PT_THREAD(metrics_tick_pt(struct pt *pt, time_t loop_timestamp));

/* Call when a call is answered (2xx). */
void metrics_call_active(void);

/* Call when an active call ends (BYE, timeout, error). */
void metrics_call_inactive(void);

#endif
