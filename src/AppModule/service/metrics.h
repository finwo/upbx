/*
 * Metrics module: registers metrics.* commands with the API server,
 * maintains call load-average state.
 */
#ifndef UPBX_SERVICE_METRICS_H
#define UPBX_SERVICE_METRICS_H

struct upbx_config;

/* Register metrics commands with the API server and initialise state.
 * Call after api_start() but before the main loop. */
void metrics_init(struct upbx_config *cfg);

/* Update load-average EMAs. Call once per main loop iteration. */
void metrics_tick(void);

/* Call when a call is answered (2xx). */
void metrics_call_active(void);

/* Call when an active call ends (BYE, timeout, error). */
void metrics_call_inactive(void);

#endif
