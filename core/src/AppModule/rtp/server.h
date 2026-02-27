#ifndef __APPMODULE_RTP_SERVER_H__
#define __APPMODULE_RTP_SERVER_H__

#include <stddef.h>
#include "RespModule/resp.h"

void rtp_server_start(void);
void rtp_server_stop(void);
int rtp_server_is_running(void);

#endif