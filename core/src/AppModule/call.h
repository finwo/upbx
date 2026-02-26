#ifndef UPBX_CALL_H
#define UPBX_CALL_H

#include <stddef.h>
#include <time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Maximum Call-ID length we store. */
#define CALL_ID_MAX 256

/* One party in a call (caller or callee). */
typedef struct {
  struct sockaddr_storage sip_addr;   /* SIP signaling address            */
  socklen_t              sip_len;
  char                  *id;          /* extension number or trunk name   */
  char                  *tag;         /* From-tag (party A) or To-tag (B) */
} call_party_t;

/* Unified call state: SIP session + RTP proxy sessions.
 * PBX communicates with rtpproxy via control protocol only - no RTP relay in PBX. */
typedef struct call {
  struct call *next;
  char         call_id[CALL_ID_MAX];

  call_party_t a;                     /* caller  (sent the INVITE to us)  */
  call_party_t b;                     /* callee  (set from 200 OK)        */

  /* Forking: SIP addresses we sent INVITE to (for ACK/CANCEL). */
  #define CALL_MAX_FORKS 8
  #define FORK_ACTIVE  0    /* INVITE sent, waiting for response          */
  #define FORK_DONE    1    /* Final non-2xx received (not retryable)     */
  #define FORK_BUSY    2    /* 486 Busy received, waiting for retry       */
  struct sockaddr_storage fork_addrs[CALL_MAX_FORKS];
  socklen_t              fork_lens[CALL_MAX_FORKS];
  char                  *fork_ids[CALL_MAX_FORKS];
  char                  *fork_vias[CALL_MAX_FORKS]; /* Via value we used (for CANCEL) */
  int                    fork_state[CALL_MAX_FORKS]; /* FORK_ACTIVE/DONE/BUSY */
  size_t                 n_forks;

  /* Extensions pending (re-)INVITE: initially populated by fork setup,
   * repopulated when a fork responds 486 Busy. The pending handler in
   * overflow_pt drains this list by sending INVITEs when extensions are free. */
  char                  *pending_exts[CALL_MAX_FORKS];
  size_t                 n_pending_exts;

  /* rtpproxy session info (for SDP and session management).
   * PBX talks to rtpproxy via control protocol - these store session state. */
  char               rtp_proxy_ip_caller[64];   /* IP from rtpproxy for caller side SDP */
  char               rtp_proxy_ip_callee[64];   /* IP from rtpproxy for callee side SDP */
  int                rtp_port_caller;           /* port from rtpproxy for caller side SDP */
  int                rtp_port_callee;           /* port from rtpproxy for callee side SDP */
  char               rtp_session_caller[64];    /* session handle from rtpproxy (from_tag) */
  char               rtp_session_callee[64];    /* session handle from rtpproxy (to_tag) */
  char               transport_caller[4];       /* "udp" or "tcp" for caller */
  char               transport_callee[4];       /* "udp" or "tcp" for callee */

  /* SIP state */
  int           sockfd;               /* UDP socket used for SIP sending  */
  int           answered;
  int           cancelling;            /* CANCEL sent to forks, awaiting 487 */
  time_t        created_at;
  time_t        answered_at;

  char         *original_invite;      /* stored for ACK/BYE generation    */
  size_t        original_invite_len;
  char         *caller_via;           /* caller's first Via (restored on responses) */

  /* Routing / plugin metadata */
  char         *trunk_name;           /* trunk name (NULL for ext-to-ext) */
  int           trunk_sdp_is_tcp;     /* transport from trunk's SDP (1=TCP, 0=UDP) */
  int           ext_sdp_is_tcp;       /* transport from extension's SDP (1=TCP, 0=UDP, -1=not specified) */
  char         *source_str;           /* caller id (for plugins)          */
  char         *dest_str;             /* callee id (for plugins)          */
  char         *direction;            /* "dialin" or "dialout" (for CALL.ANSWER/HANGUP events) */
  int           overflow_done;
} call_t;

/* Pre-remove callback (for plugin notifications) */

/* Called before a call is removed from the list. Set once at startup. */
typedef void (*call_pre_remove_cb)(call_t *call);
void call_set_pre_remove_callback(call_pre_remove_cb cb);

/* Lifecycle */

/* Allocate a new call, set call_id and created_at. Returns NULL on failure. */
call_t *call_create(const char *call_id);

/* Find a call by Call-ID. Returns NULL if not found. */
call_t *call_find(const char *call_id);

/* Remove a call: cleanup rtpproxy sessions, free strings, unlink from list. */
void call_remove(call_t *call);

/* Return the head of the call list (for iteration). */
call_t *call_first(void);

/* rtpproxy session management (via control protocol) */

/* Create an rtpproxy session for one side of a call.
 * Calls rtpp_update() via rtpproxy_client to create session.
 * On success: stores session handle, proxy IP, port in call struct.
 * Returns 0 on success, -1 on failure. */
int call_rtpproxy_session_create(call_t *call, int side_caller,
                                  const char *from_tag, const char *to_tag);

/* Delete rtpproxy sessions for a call.
 * Calls rtpp_delete() via rtpproxy_client for both sides.
 * Returns 0 on success, -1 on failure (errors logged, doesn't fail call removal). */
int call_rtpproxy_session_delete(call_t *call);

/* Remove calls that have been idle for more than timeout_sec. */
void call_age_idle(int timeout_sec);

/* Set transport for a party (call_t, side_caller=1 or side_callee=0) */
void call_set_transport(call_t *call, int side_a, const char *transport);

#endif