#ifndef UPBX_PBX_TRUNK_H
#define UPBX_PBX_TRUNK_H

#include <regex.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "common/scheduler.h"
#include "domain/pbx/sip_parser.h"

typedef struct {
  char   *pattern;
  char   *replacement;
  regex_t compiled;
} trunk_rewrite_rule_t;

typedef struct {
  char                 *name;
  char                 *protocol;
  char                 *host;
  int                   port;
  char                 *username;
  char                 *password;
  char                 *cid;
  char                **dids;
  size_t                did_count;
  char                **groups;
  size_t                group_count;
  trunk_rewrite_rule_t *rewrite_rules;
  size_t                rewrite_rule_count;
} trunk_config_t;

typedef struct {
  trunk_config_t *cfg;

  /* socket */
  int                     fd;
  int                     fds[2];     /* sched_has_data format: [0]=count, [1]=fd */
  int                     local_port; /* ephemeral port assigned to fd */
  struct sockaddr_storage remote_addr;
  socklen_t               remote_addr_len;

  /* registration timing */
  time_t registered_at;
  time_t next_register;
  int    expires_seconds;

  /* backoff */
  int retry_count;

  /* transaction state */
  char call_id[64];
  int  cseq;

  /* auth challenge */
  char *nonce;
  char *realm;
  int   auth_challenged;

  /* receive buffer */
  char recv_buf[4096];
} trunk_state_t;

void pbx_trunk_init(void);
void pbx_trunk_shutdown(void);
void pbx_trunk_reload(void);

int trunk_register_pt(int64_t timestamp, struct pt_task *task);

/* --- Outbound routing API --- */

/* Check if a trunk is currently registered (has a valid, non-expired registration). */
int pbx_trunk_is_registered(trunk_state_t *state);

/* Retrieve trunks matching a group.  Returns count of matching trunks.
 * Fills caller-supplied arrays of config and state pointers (up to max_out).
 * Trunks are returned in config-file order. */
size_t pbx_trunk_get_by_group(const char *group, trunk_config_t **cfgs_out, trunk_state_t **states_out, size_t max_out);

/* Apply the first matching rewrite rule from a trunk to dialed_number.
 * Returns a newly-allocated string with the rewritten number, or a
 * strdup of the original if no rule matched.  Caller must free. */
char *pbx_trunk_apply_rewrite(const trunk_config_t *cfg, const char *dialed_number);

/* Handle a call-related response that arrived for a trunk call.
 * Looks up the trunk by name and dispatches to the response handler.
 * Returns 0 if handled, -1 if trunk not found. */
int pbx_trunk_dispatch_call_response(const char *trunk_name, sip_message_t *msg);

/* Handle a response from an extension to a forked inbound call leg.
 * Returns 0 if handled (was an inbound call leg response), -1 otherwise. */
int pbx_trunk_dispatch_inbound_leg_response(sip_message_t *msg, const char *extension);

/* Find trunk name for an inbound call by call_id.
 * Returns trunk name or NULL if not found. Caller must not free. */
const char *pbx_trunk_find_name_for_inbound_call(const char *call_id);

#endif
