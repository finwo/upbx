#ifndef GW_REGISTRATION_H
#define GW_REGISTRATION_H

#include <sys/socket.h>
#include <time.h>

// Save registration to disk (both by-ext and by-adr files)
void registration_save(const char *data_dir, const char *extension,
                       struct sockaddr_storage *remote_addr,
                       const char *contact, const char *pbx_addr, time_t expires);

// Delete registration from disk
void registration_delete(const char *data_dir, const char *extension);

// Load registration from disk by extension (returns 1 if found+valid)
int registration_load(const char *data_dir, const char *extension,
                      struct sockaddr_storage *remote_addr_out,
                      char **contact_out, char **pbx_addr_out, time_t *expires_out);

// Lookup extension by source address (returns malloc'd extension string or NULL)
char *registration_find_by_addr(const char *data_dir, struct sockaddr_storage *src);

// Cleanup: check one random registration for expiry, delete if expired
void registration_cleanup_once(const char *data_dir);

#endif
