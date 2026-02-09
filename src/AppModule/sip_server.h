#ifndef UPBX_SIP_SERVER_H
#define UPBX_SIP_SERVER_H

#include "config.h"

/* Main entry for daemon: runs select loop, SIP, RTP relay, trunk reg, overflow.
 * argv[0] = upbx_config*. Daemon calls this and does not return. */
void daemon_root(int argc, void *argv[]);

#endif
