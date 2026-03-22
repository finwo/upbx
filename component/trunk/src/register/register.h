#ifndef TRK_REGISTER_H
#define TRK_REGISTER_H

struct trunk_state;

/* Send initial REGISTER (no auth). */
void trunk_send_register(struct trunk_state *ts);

/* Send REGISTER with auth after 401 challenge. */
void trunk_send_register_auth(struct trunk_state *ts, const char *www_auth);

#endif
