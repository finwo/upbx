/*
 * Extension registration state: tracks which extensions are currently registered,
 * on which trunk, with what contact info and learned address.
 *
 * Owned data: callers receive pointers into the internal list; do not free them.
 */
#ifndef UPBX_REGISTRATION_H
#define UPBX_REGISTRATION_H

#include <stddef.h>
#include <time.h>

typedef struct {
  char *number;       /* Extension number (e.g. "206") for config lookup */
  char *uri_user;     /* Original username from REGISTER (e.g. "206%40finwo") */
  char *trunk_name;
  char *contact;
  char learned_host[256];
  char learned_port[32];
  char *plugin_data;  /* Optional custom data from plugin ALLOW */
  time_t expires;
} ext_reg_t;

/* Initialize the registration subsystem (must be called once before use). */
void registration_init(void);

/* Notify-pending flag: set internally after a registration change, cleared after notification. */
void registration_clear_notify_pending(void);
int  registration_is_notify_pending(void);

/* Add or update a registration. Takes ownership of all string arguments (caller must not free).
 * learned_host and learned_port are copied (not transferred). */
void registration_update(char *number, char *uri_user, const char *trunk_name,
    char *contact, const char *learned_host, const char *learned_port,
    char *plugin_data);

/* Find one registration by trunk and number. Returns NULL if not found or expired. */
ext_reg_t *registration_get_by_number(const char *trunk_name, const char *number);

/* Flexible query: filter by trunk_name (NULL = any) and/or ext_number (NULL = any).
 * *out is an allocated array of pointers (caller frees the array, not the elements). Returns count. */
size_t registration_get_regs(const char *trunk_name, const char *ext_number, ext_reg_t ***out);

/* Get trunk name for an extension ("" if not registered). Caller does not free. */
const char *registration_get_trunk_for_ext(const char *ext_number);

/* Learned advertise address (from Request-URI of REGISTER). */
void registration_set_advertise_addr(const char *host, const char *port);
int  registration_get_advertise_addr(char *host_out, size_t host_size, char *port_out, size_t port_size);

#endif
