#ifndef UPBX_SIP_SERVER_H
#define UPBX_SIP_SERVER_H

#include "config.h"

/* Root coroutine for daemon: starts SIP server then yields forever
 * argv[0] = upbx_config*. Daemon should neco_start(this, 1, &cfg). */
void daemon_root(int argc, void *argv[]);

#endif
