#ifndef __APPMODULE_PBX_TRUNK_REG_H__
#define __APPMODULE_PBX_TRUNK_REG_H__

#include <time.h>
#include <stdint.h>

#include "common/pt.h"

struct pt_task;

typedef struct {
  char *name;
  char *host;
  int port;
  char transport[8];
  char *username;
  char *password;
  int registered;
  time_t expires;
  time_t last_register;
  char *contact;
  char *via_addr;
  int via_port;
  int fd;
  struct pt pt;
} trunk_reg_t;

void trunk_reg_start_all(void);
void trunk_reg_stop_all(void);
void trunk_reg_tick(void);
trunk_reg_t *trunk_reg_find(const char *name);

const char *trunk_reg_get_contact(const char *name);
int trunk_reg_is_registered(const char *name);
int trunk_reg_is_available(const char *name);

#endif