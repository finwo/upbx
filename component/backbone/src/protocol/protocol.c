#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include "protocol/protocol.h"
#include "auth/auth.h"
#include "user/user.h"
#include "config/config.h"
#include "finwo/mindex.h"
#include "finwo/scheduler.h"
#include "rxi/log.h"

#define MAX_LINE 4096
#define AUTH_TIMEOUT_SEC 10
#define PEER_RECONNECT_SEC 5
#define CANCEL_DELAY_MS 100

struct call_key {
    const char *call_id;
    size_t call_id_len;
};

static int call_cmp(const void *a, const void *b, void *udata) {
    (void)udata;
    const struct upbx_call *ca = a;
    const struct call_key *cb = b;
    size_t len = ca->call_id_len < cb->call_id_len ? ca->call_id_len : cb->call_id_len;
    int r = strncmp(ca->call_id, cb->call_id, len);
    if (r != 0) return r;
    return (int)(ca->call_id_len - cb->call_id_len);
}

static void call_purge(void *item, void *udata) {
    (void)udata;
    struct upbx_call *c = item;
    free(c->call_id);
    free(c->did);
    free(c->cid);
    free(c);
}

struct conn {
    struct pt_task task;
    int fd;
    int authenticated;
    char *username;
    char *recv_buf;
    size_t recv_len;
    size_t recv_cap;
    time_t connected_at;
    struct upbx_protocol_ctx *proto;
    struct conn *next;
};

enum peer_phase {
    PEER_DISCONNECTED,
    PEER_WAIT_AUTH_REPLY,
    PEER_CONNECTED
};

struct peer_state {
    struct upbx_peer_config *peer_cfg;
    struct upbx_protocol_ctx *proto;
    struct conn *conn;
    int fd;               /* fd during handshake, before conn is created */
    enum peer_phase phase;
    char recv_buf[512];
    size_t recv_len;
    time_t last_attempt;
};

static void conn_close(struct conn *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

static void conn_free(struct conn *c) {
    if (c->proto) {
        struct conn **prev = (struct conn **)&c->proto->conns;
        while (*prev && *prev != c) prev = &(*prev)->next;
        if (*prev == c) *prev = c->next;
    }
    conn_close(c);
    free(c->recv_buf);
    free(c->username);
    free(c);
}

static void conn_send(int fd, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return;
        sent += (size_t)n;
    }
}

static void conn_sendf(int fd, const char *fmt, ...) {
    char buf[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len > 0) conn_send(fd, buf, (size_t)len);
}

static int conn_recv_line(struct conn *c, char *out, size_t out_size) {
    if (c->fd < 0) return -1;
    char buf[1024];
    ssize_t n = recv(c->fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;

    if (c->recv_len + (size_t)n + 1 > c->recv_cap) {
        c->recv_cap = (c->recv_len + (size_t)n + 4096) * 2;
        c->recv_buf = realloc(c->recv_buf, c->recv_cap);
    }
    memcpy(c->recv_buf + c->recv_len, buf, (size_t)n);
    c->recv_len += (size_t)n;
    c->recv_buf[c->recv_len] = '\0';

    char *newline = strchr(c->recv_buf, '\n');
    if (!newline) return 1;

    size_t line_len = newline - c->recv_buf;
    if (line_len >= out_size) line_len = out_size - 1;
    memcpy(out, c->recv_buf, line_len);
    out[line_len] = '\0';

    size_t remaining = c->recv_len - line_len - 1;
    memmove(c->recv_buf, newline + 1, remaining + 1);
    c->recv_len = remaining;

    return 0;
}

static void conn_authenticate(struct conn *c, char *args) {
    char username[256] = {0};
    char nonce[64] = {0};
    char signature[256] = {0};

    while (*args == ' ') args++;
    char *space = strchr(args, ' ');
    if (!space) { conn_close(c); return; }

    size_t user_part_len = space - args;
    if (user_part_len >= sizeof(username)) user_part_len = sizeof(username) - 1;
    memcpy(username, args, user_part_len);
    username[user_part_len] = '\0';

    char *sig = space + 1;
    while (*sig == ' ') sig++;
    if (strlen(sig) < 128) { conn_close(c); return; }
    strncpy(signature, sig, sizeof(signature) - 1);

    char *colon = strchr(username, ':');
    if (!colon) { conn_close(c); return; }
    size_t name_len = colon - username;
    memcpy(nonce, colon + 1, 63);
    nonce[63] = '\0';
    username[name_len] = '\0';

    int verified = -1;

    if (username[0] != '\0') {
        struct upbx_user *user = upbx_user_registry_find(c->proto->user_reg, username);
        if (user && user->has_pubkey) {
            verified = upbx_auth_verify_user(user->public_key, username, nonce, signature);
        }
    } else if (c->proto->config && c->proto->config->has_cluster_key) {
        verified = upbx_auth_verify_cluster(c->proto->config->cluster_pubkey, nonce, signature);
    }

    if (verified == 0) {
        c->authenticated = 1;
        c->username = username[0] ? strdup(username) : NULL;
        conn_send(c->fd, "ok\n", 3);
        log_info("protocol: authenticated %s", c->username ? c->username : "(peer)");
    } else {
        conn_send(c->fd, "err auth\n", 9);
        conn_close(c);
    }
}

/* ── Call signalling handlers ────────────────────────────────────── */

static void handle_invite(struct conn *c, char *line) {
    char call_id[256] = {0}, did[256] = {0}, cid[256] = {0};
    if (sscanf(line, "invite %255s %255s %255s", call_id, did, cid) < 3) return;

    struct call_key key = {call_id, strlen(call_id)};
    struct upbx_call *call = mindex_get(c->proto->calls, &key);

    /* Dedup: if call-id already known, drop entirely */
    if (call) return;

    call = calloc(1, sizeof(struct upbx_call));
    call->call_id = strdup(call_id);
    call->call_id_len = strlen(call_id);
    call->did = strdup(did);
    call->cid = strdup(cid);
    call->caller_fd = c->fd;
    call->state = UPBX_CALL_PENDING;
    mindex_set(c->proto->calls, call);

    /* Forward to all other authenticated connections (clients + peers) */
    for (struct conn *pc = c->proto->conns; pc; pc = pc->next) {
        if (pc != c && pc->authenticated) {
            conn_sendf(pc->fd, "%s\n", line);
        }
    }
}

static void handle_ringing(struct conn *c, char *line) {
    char call_id[256] = {0};
    if (sscanf(line, "ringing %255s", call_id) < 1) return;

    struct call_key key = {call_id, strlen(call_id)};
    struct upbx_call *call = mindex_get(c->proto->calls, &key);
    if (!call) return;

    /* Collapse on first ringing: select callee, cancel all others */
    if (call->state < UPBX_CALL_RINGING && call->caller_fd >= 0 && call->caller_fd != c->fd) {
        call->callee_fd = c->fd;
        call->state = UPBX_CALL_RINGING;
        conn_sendf(call->caller_fd, "ringing %s\n", call_id);

        /* Cancel all other connections (except caller and ringing sender) */
        for (struct conn *pc = c->proto->conns; pc; pc = pc->next) {
            if (pc->authenticated && pc->fd != c->fd && pc->fd != call->caller_fd) {
                conn_sendf(pc->fd, "cancel %s\n", call_id);
            }
        }
    }
}

static void handle_answer(struct conn *c, char *line) {
    char call_id[256] = {0};
    if (sscanf(line, "answer %255s", call_id) < 1) return;

    struct call_key key = {call_id, strlen(call_id)};
    struct upbx_call *call = mindex_get(c->proto->calls, &key);

    /* Unknown call: drop */
    if (!call) return;

    /* Already active: double-pickup race -- send bye back to late answerer */
    if (call->state == UPBX_CALL_ACTIVE) {
        conn_sendf(c->fd, "bye %s\n", call_id);
        return;
    }

    /* Set callee and activate */
    call->callee_fd = c->fd;
    call->state = UPBX_CALL_ACTIVE;

    /* Send answer to caller */
    if (call->caller_fd >= 0) {
        conn_sendf(call->caller_fd, "answer %s\n", call_id);
    }
}

struct delayed_cancel {
    char call_id[256];
    int sender_fd;
    struct upbx_protocol_ctx *proto;
    int64_t fire_at;
};

static int delayed_cancel_task(int64_t ts, struct pt_task *pt) {
    struct delayed_cancel *dc = pt->udata;
    if (ts < dc->fire_at) return SCHED_RUNNING;

    struct call_key key = {dc->call_id, strlen(dc->call_id)};
    struct upbx_call *call = mindex_get(dc->proto->calls, &key);

    /* Call gone or already ringing/active/ended: drop */
    if (!call || call->state >= UPBX_CALL_RINGING) {
        free(dc);
        return SCHED_DONE;
    }

    /* Forward cancel to all other authenticated connections except original sender */
    for (struct conn *pc = dc->proto->conns; pc; pc = pc->next) {
        if (pc->authenticated && pc->fd != dc->sender_fd) {
            conn_sendf(pc->fd, "cancel %s\n", dc->call_id);
        }
    }

    call->state = UPBX_CALL_ENDED;
    mindex_delete(dc->proto->calls, &key);
    free(dc);
    return SCHED_DONE;
}

static void handle_cancel(struct conn *c, char *line) {
    char call_id[256] = {0};
    if (sscanf(line, "cancel %255s", call_id) < 1) return;

    struct call_key key = {call_id, strlen(call_id)};
    struct upbx_call *call = mindex_get(c->proto->calls, &key);

    /* Unknown call: drop */
    if (!call) return;

    /* Already ringing/active/ended: drop */
    if (call->state >= UPBX_CALL_RINGING) return;

    /* Schedule delayed cancel */
    struct timeval now;
    gettimeofday(&now, NULL);
    int64_t now_ms = (int64_t)now.tv_sec * 1000 + now.tv_usec / 1000;

    struct delayed_cancel *dc = calloc(1, sizeof(struct delayed_cancel));
    strncpy(dc->call_id, call_id, sizeof(dc->call_id) - 1);
    dc->sender_fd = c->fd;
    dc->proto = c->proto;
    dc->fire_at = now_ms + CANCEL_DELAY_MS;
    sched_create(delayed_cancel_task, dc);
}

static void handle_media(struct conn *c, char *line) {
    char call_id[256] = {0};
    if (sscanf(line, "media %255s", call_id) < 1) return;

    struct call_key key = {call_id, strlen(call_id)};
    struct upbx_call *call = mindex_get(c->proto->calls, &key);
    if (!call || call->state != UPBX_CALL_ACTIVE) return;

    int other_fd = -1;
    if (call->caller_fd == c->fd) other_fd = call->callee_fd;
    else if (call->callee_fd == c->fd) other_fd = call->caller_fd;
    else return;

    if (other_fd >= 0) conn_sendf(other_fd, "%s\n", line);
}

static void handle_bye(struct conn *c, char *line) {
    char call_id[256] = {0};
    if (sscanf(line, "bye %255s", call_id) < 1) return;

    struct call_key key = {call_id, strlen(call_id)};
    struct upbx_call *call = mindex_get(c->proto->calls, &key);

    /* Unknown call: drop */
    if (!call) return;

    int other_fd = -1;
    if (call->caller_fd == c->fd) other_fd = call->callee_fd;
    else if (call->callee_fd == c->fd) other_fd = call->caller_fd;
    else return;

    if (other_fd >= 0) conn_sendf(other_fd, "bye %s\n", call_id);
    call->state = UPBX_CALL_ENDED;
    mindex_delete(c->proto->calls, &key);
}

/* ── Connection task (handles both client and peer connections) ─── */

static int conn_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct conn *c = pt->udata;

    if (c->fd < 0) return SCHED_DONE;

    time_t age = time(NULL) - c->connected_at;
    if (!c->authenticated && age > AUTH_TIMEOUT_SEC) {
        conn_close(c);
        return SCHED_DONE;
    }

    int fds[2] = {1, c->fd};
    if (sched_has_data(fds) < 0) return SCHED_RUNNING;

    char line[MAX_LINE];
    int ret = conn_recv_line(c, line, sizeof(line));
    if (ret < 0) return SCHED_DONE;
    if (ret > 0) return SCHED_RUNNING;

    char *p = line;
    while (*p == ' ') p++;
    char *space = strchr(p, ' ');
    char cmd[64] = {0};
    if (space) {
        size_t len = space - p;
        if (len >= sizeof(cmd)) len = sizeof(cmd) - 1;
        memcpy(cmd, p, len);
    } else {
        strncpy(cmd, p, sizeof(cmd) - 1);
    }

    if (strcmp(cmd, "auth") == 0) {
        conn_authenticate(c, line + 4);
    } else if (strcmp(cmd, "ping") == 0) {
        conn_send(c->fd, "pong\n", 5);
    } else if (!c->authenticated) {
        /* Drop non-auth commands from unauthenticated connections */
    } else if (strcmp(cmd, "invite") == 0) {
        handle_invite(c, line);
    } else if (strcmp(cmd, "ringing") == 0) {
        handle_ringing(c, line);
    } else if (strcmp(cmd, "answer") == 0) {
        handle_answer(c, line);
    } else if (strcmp(cmd, "cancel") == 0) {
        handle_cancel(c, line);
    } else if (strcmp(cmd, "media") == 0) {
        handle_media(c, line);
    } else if (strcmp(cmd, "bye") == 0) {
        handle_bye(c, line);
    }

    return SCHED_RUNNING;
}

/* ── Listener task (accepts inbound connections) ─────────────────── */

static int listener_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct upbx_protocol_ctx *ctx = pt->udata;

    if (!ctx->listen_fds) return SCHED_RUNNING;

    int ready = sched_has_data(ctx->listen_fds);
    if (ready < 0) return SCHED_RUNNING;

    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    int fd = accept(ready, (struct sockaddr *)&ss, &sslen);
    if (fd < 0) return SCHED_RUNNING;

    struct conn *c = calloc(1, sizeof(struct conn));
    c->fd = fd;
    c->connected_at = time(NULL);
    c->proto = ctx;
    c->next = (struct conn *)ctx->conns;
    ctx->conns = (void *)c;
    sched_create(conn_task, c);

    log_debug("protocol: new connection fd=%d", fd);
    return SCHED_RUNNING;
}

/* ── Peer outbound connection task ───────────────────────────────── */

static int peer_connect_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int peer_connect_tcp(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port ? port : "5070", &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int peer_connect_task(int64_t ts, struct pt_task *pt) {
    (void)ts;
    struct peer_state *ps = pt->udata;

    /* If connected, monitor the connection */
    if (ps->phase == PEER_CONNECTED) {
        if (ps->conn && ps->conn->fd >= 0) return SCHED_RUNNING;
        /* Connection died */
        if (ps->conn) { conn_free(ps->conn); ps->conn = NULL; }
        ps->phase = PEER_DISCONNECTED;
    }

    /* Waiting for auth reply */
    if (ps->phase == PEER_WAIT_AUTH_REPLY) {
        int fds[2] = {1, ps->fd};
        if (sched_has_data(fds) < 0) {
            /* Check timeout */
            if (time(NULL) - ps->last_attempt > AUTH_TIMEOUT_SEC) {
                log_error("protocol: peer auth timeout to %s", ps->peer_cfg->url);
                close(ps->fd);
                ps->fd = -1;
                ps->phase = PEER_DISCONNECTED;
            }
            return SCHED_RUNNING;
        }

        /* Read response bytes */
        ssize_t n = recv(ps->fd, ps->recv_buf + ps->recv_len,
                         sizeof(ps->recv_buf) - ps->recv_len - 1, 0);
        if (n <= 0) {
            close(ps->fd);
            ps->fd = -1;
            ps->phase = PEER_DISCONNECTED;
            return SCHED_RUNNING;
        }
        ps->recv_len += (size_t)n;
        ps->recv_buf[ps->recv_len] = '\0';

        char *nl = strchr(ps->recv_buf, '\n');
        if (!nl) return SCHED_RUNNING;
        *nl = '\0';

        if (strncmp(ps->recv_buf, "ok", 2) != 0) {
            log_error("protocol: peer auth rejected by %s: %s", ps->peer_cfg->url, ps->recv_buf);
            close(ps->fd);
            ps->fd = -1;
            ps->phase = PEER_DISCONNECTED;
            return SCHED_RUNNING;
        }

        /* Auth succeeded -- promote to conn */
        struct conn *c = calloc(1, sizeof(struct conn));
        c->fd = ps->fd;
        c->connected_at = ps->last_attempt;
        c->authenticated = 1;
        c->username = NULL;
        c->proto = ps->proto;
        c->next = (struct conn *)ps->proto->conns;
        ps->proto->conns = (void *)c;
        sched_create(conn_task, c);
        ps->conn = c;
        ps->fd = -1;
        ps->phase = PEER_CONNECTED;
        log_info("protocol: connected to peer %s fd=%d", ps->peer_cfg->url, c->fd);
        return SCHED_RUNNING;
    }

    /* PEER_DISCONNECTED -- throttle reconnect */
    time_t now = time(NULL);
    if (now - ps->last_attempt < PEER_RECONNECT_SEC) return SCHED_RUNNING;
    ps->last_attempt = now;

    /* Connect */
    int fd = -1;
    struct upbx_peer_config *pcfg = ps->peer_cfg;
    if (pcfg->scheme && strcmp(pcfg->scheme, "unix") == 0) {
        fd = peer_connect_unix(pcfg->path);
    } else {
        fd = peer_connect_tcp(pcfg->host ? pcfg->host : pcfg->address, pcfg->port);
    }
    if (fd < 0) {
        log_debug("protocol: peer connect failed to %s", pcfg->url);
        return SCHED_RUNNING;
    }

    /* Send auth */
    if (!ps->proto->config || !ps->proto->config->has_cluster_key) {
        log_error("protocol: no cluster key, cannot auth to peer %s", pcfg->url);
        close(fd);
        return SCHED_RUNNING;
    }

    char auth_line[512];
    if (upbx_auth_sign_cluster(
            ps->proto->config->cluster_pubkey,
            ps->proto->config->cluster_privkey,
            auth_line, sizeof(auth_line)) < 0) {
        close(fd);
        return SCHED_RUNNING;
    }
    size_t auth_len = strlen(auth_line);
    auth_line[auth_len] = '\n';
    auth_line[auth_len + 1] = '\0';
    conn_send(fd, auth_line, auth_len + 1);

    ps->fd = fd;
    ps->recv_len = 0;
    ps->recv_buf[0] = '\0';
    ps->phase = PEER_WAIT_AUTH_REPLY;
    return SCHED_RUNNING;
}

/* ── Public API ──────────────────────────────────────────────────── */

struct upbx_protocol_ctx *upbx_protocol_create(void) {
    struct upbx_protocol_ctx *ctx = calloc(1, sizeof(struct upbx_protocol_ctx));
    ctx->calls = mindex_init(call_cmp, call_purge, NULL);
    return ctx;
}

void upbx_protocol_free(struct upbx_protocol_ctx *ctx) {
    if (!ctx) return;
    struct conn *c = ctx->conns;
    while (c) {
        struct conn *next = c->next;
        conn_free(c);
        c = next;
    }
    if (ctx->listen_fds) free(ctx->listen_fds);
    mindex_free(ctx->calls);
    free(ctx);
}

void upbx_protocol_start(struct upbx_protocol_ctx *ctx) {
    sched_create(listener_task, ctx);

    /* Start outbound peer connections */
    if (ctx->config) {
        for (struct upbx_peer_config *pcfg = ctx->config->peers; pcfg; pcfg = pcfg->next) {
            struct peer_state *ps = calloc(1, sizeof(struct peer_state));
            ps->peer_cfg = pcfg;
            ps->proto = ctx;
            sched_create(peer_connect_task, ps);
        }
    }
}
