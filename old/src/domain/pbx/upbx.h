#ifndef UPBX_PBX_UPBX_H
#define UPBX_PBX_UPBX_H

#include <stdint.h>
#include <sys/socket.h>
#include <stdbool.h>
#include "common/scheduler.h"
#include "domain/pbx/media_proxy.h"

#define MEDIA_MAX   8          /* max media streams per call */
#define SDP_MAX    4096        /* generous buffer for SDP */

/* --------------------------------------------------------------------- */
/* Registration list – holds both extensions and trunks                */
enum registration_type {
    REG_EXT,      /* extension */
    REG_TRUNK     /* trunk */
};

struct registration {
    enum registration_type type;      /* extension or trunk            */
    char *id;                               /* ext number or trunk name     */
    char *pbx_addr;                         /* IP/port remote sees us as   */
    struct sockaddr_storage *remote_addr;  /* remote UDP endpoint          */
    time_t expires;                         /* registration expiry epoch   */
    char *group_prefix;                     /* group prefix for extensions */
    char *secret;                           /* secret for digest auth      */
    char *realm;                            /* realm for digest auth       */

    /* Call tracking */
    struct call **active_calls;             /* dynamic array of calls       */
    size_t active_call_cnt;
    size_t active_call_cap;
};

/* --------------------------------------------------------------------- */
/* Call representation – one B2BUA dialog (two legs)                    */
struct call {
    char *call_id;                     /* from original INVITE               */
    struct registration *src;          /* who originated the call            */
    struct registration *dst;          /* final destination (NULL while ringing) */

    int src_media_fd[MEDIA_MAX];        /* wormhole sockets for source leg    */
    int dst_media_fd[MEDIA_MAX];        /* wormhole sockets for dest leg      */
    int src_media_count;                /* number of active media streams */
    int dst_media_count;                /* number of active media streams */

    char src_sdp[SDP_MAX];
    char dst_sdp[SDP_MAX];

    enum { CALL_INCOMING, CALL_OUTGOING } direction;
    uint64_t last_activity;            /* ms since epoch – for timeout       */

    /* Pending INVITE(s) when ringing a group */
    struct invite **pending_invites;
    size_t pending_cnt;
    size_t pending_cap;
};

/* --------------------------------------------------------------------- */
/* Simple INVITE holder used while group‑ringing                         */
struct invite {
    struct registration *target;   /* extension we sent INVITE to          */
    char *branch;                  /* via branch for matching responses    */
    int state;                     /* 0 = waiting, 1 = answered, -1 = cancelled */
};

/* --------------------------------------------------------------------- */
/* Main data structure passed to protothreads                           */
struct main_data {
    struct list *registrations;
    int *read_fds;                 /* UDP socket file descriptors from udp_recv */
    int maxfd;
    int64_t now_ms;                /* current timestamp in milliseconds */
};

/* SIP method definitions */
enum sip_method {
    SIP_METHOD_INVITE,
    SIP_METHOD_ACK,
    SIP_METHOD_OPTION,
    SIP_METHOD_BYE,
    SIP_METHOD_CANCEL,
    SIP_METHOD_REGISTER,
    SIP_METHOD_MESSAGE,
    SIP_METHOD_INFO,
    SIP_METHOD_SUBSCRIBE,
    SIP_METHOD_NOTIFY,
    SIP_METHOD_REFER,
    SIP_METHOD_UNKNOWN
};

#endif /* UPBX_PBX_UPBX_H */