/*
 * Trunk registration: periodic REGISTER to upstream trunks (SIP client).
 * Run as a neco coroutine; started from sip_server_main.
 */
#ifndef UPBX_TRUNK_REG_H
#define UPBX_TRUNK_REG_H

struct upbx_config;

/* Coroutine entry: run trunk registration loop (never returns).
 * argc/argv: argv[0] = upbx_config *cfg */
void trunk_reg_loop(int argc, void *argv[]);

#endif
