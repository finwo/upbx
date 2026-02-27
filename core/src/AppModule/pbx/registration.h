#ifndef __APPMODULE_PBX_REGISTRATION_H__
#define __APPMODULE_PBX_REGISTRATION_H__

#include <time.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  char *number;
  char *name;
  char *contact;
  struct sockaddr_storage remote_addr;
  int tcp_fd;
  time_t expires;
  time_t registered_at;
  char *realm;
  char *nonce;
  char *trunk_name;
} extension_reg_t;

extension_reg_t *registration_find(const char *number);
void registration_add(const char *number, const char *contact, const struct sockaddr *remote_addr, int tcp_fd, time_t expires);
void registration_remove(const char *number);
void registration_cleanup(void);
void registration_notify_plugins(void);

const char *registration_get_contact(const char *number);
const char *registration_get_advertise_addr(const char *number, char *buf, size_t buf_len);

size_t registration_get_regs(const char *trunk_name, const char *ext_number, extension_reg_t ***out);

#endif