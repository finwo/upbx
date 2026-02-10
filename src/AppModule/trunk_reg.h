/*
 * Trunk registration: periodic REGISTER to upstream trunks (SIP client).
 * Single-threaded: main loop calls fill_fds/poll; protothread drives when to send.
 */
#ifndef UPBX_TRUNK_REG_H
#define UPBX_TRUNK_REG_H

#include <sys/select.h>

struct upbx_config;
struct pt;

/* Call once at daemon start (after config load). */
void trunk_reg_start(struct upbx_config *cfg);

/* Add any in-flight registration socket fds to the set. */
void trunk_reg_fill_fds(fd_set *read_set, int *maxfd);

/* For each fd in read_set that is a trunk reg socket, recv and handle response. */
void trunk_reg_poll(fd_set *read_set);

/* Protothread: decides when to start registration for each trunk. Schedule from main loop. */
char trunk_reg_pt(struct pt *pt, struct upbx_config *cfg);

/* Check whether a trunk's upstream registration is currently active (2xx received). */
int trunk_reg_is_available(const char *trunk_name);

#endif
