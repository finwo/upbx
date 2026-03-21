#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include "rxi/log.h"
#include "finwo/pbkdf2.h"
#include "finwo/scheduler.h"
#include "orlp/ed25519.h"
#include "backbone/backbone.h"
#include "pbx/pbx.h"

#define RECONNECT_INTERVAL 5
#define AUTH_TIMEOUT        10
#define PBKDF2_ITERATIONS   10000

// Forward-declared callbacks from pbx (defined in pbx.c)
extern void pbx_on_backbone_ringing(struct pbx_state *s, const char *call_id, const char *codec_tags);
extern void pbx_on_backbone_answer(struct pbx_state *s, const char *call_id, const char *codec_tags);
extern void pbx_on_backbone_cancel(struct pbx_state *s, const char *call_id);
extern void pbx_on_backbone_media(struct pbx_state *s, const char *call_id, int stream_id, const uint8_t *data, size_t len);
extern void pbx_on_backbone_bye(struct pbx_state *s, const char *call_id);

// ── hex helpers ────────────────────────────────────────────────────────

static int hex_encode(const uint8_t *in, size_t in_len, char *out, size_t out_size) {
    static const char hex[] = "0123456789abcdef";
    if (out_size < in_len * 2 + 1) return -1;
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
    return (int)(in_len * 2);
}

static int hex_decode(const char *in, uint8_t *out, size_t out_size) {
    size_t in_len = strlen(in);
    if (in_len % 2 != 0) return -1;
    size_t byte_len = in_len / 2;
    if (byte_len > out_size) return -1;
    for (size_t i = 0; i < byte_len; i++) {
        char hi = in[i * 2];
        char lo = in[i * 2 + 1];
        uint8_t h, l;
        if      (hi >= '0' && hi <= '9') h = hi - '0';
        else if (hi >= 'a' && hi <= 'f') h = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') h = hi - 'A' + 10;
        else return -1;
        if      (lo >= '0' && lo <= '9') l = lo - '0';
        else if (lo >= 'a' && lo <= 'f') l = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') l = lo - 'A' + 10;
        else return -1;
        out[i] = (h << 4) | l;
    }
    return (int)byte_len;
}

// ── helpers ────────────────────────────────────────────────────────────

static void close_fd(struct backbone_state *bs) {
    if (bs->fd >= 0) {
        close(bs->fd);
        bs->fd = -1;
    }
    bs->phase = BACKBONE_DISCONNECTED;
    bs->recv_len = 0;
}

static void advance_backbone(struct backbone_state *bs) {
    if (!bs->current) {
        bs->current = bs->config->backbones;
    } else {
        bs->current = bs->current->next;
        if (!bs->current) bs->current = bs->config->backbones;
    }
    bs->fail_index++;
}

static void send_auth(struct backbone_state *bs) {
    if (!bs->current || !bs->current->username || !bs->current->password) return;

    uint8_t seed[32];
    pbkdf2((const uint8_t *)bs->current->password, strlen(bs->current->password),
           (const uint8_t *)bs->current->username, strlen(bs->current->username),
           PBKDF2_ITERATIONS, PBKDF2_SHA256,
           seed, 32);

    uint8_t pub[32], priv[64];
    ed25519_create_keypair(pub, priv, seed);

    time_t nonce = time(NULL);
    char msg[512];
    int msg_len = snprintf(msg, sizeof(msg), "%s:%ld", bs->current->username, (long)nonce);

    uint8_t sig[64];
    ed25519_sign(sig, (const uint8_t *)msg, (size_t)msg_len, pub, priv);

    char sig_hex[129];
    hex_encode(sig, 64, sig_hex, sizeof(sig_hex));

    char line[1024];
    int len = snprintf(line, sizeof(line), "auth %s:%ld %s\n",
                       bs->current->username, (long)nonce, sig_hex);
    send(bs->fd, line, (size_t)len, 0);
}

// ── line dispatch ──────────────────────────────────────────────────────

static void dispatch_line(struct backbone_state *bs, const char *line) {
    char cmd[64] = {0};
    char arg[512] = {0};
    sscanf(line, "%63s %511[^\n]", cmd, arg);

    if (strcmp(cmd, "invite") == 0) {
        // Format: invite <call_id> <did> <cid> [tags...]
        char call_id[256] = {0}, did[256] = {0}, cid[256] = {0};
        char *p = arg;

        /* Parse call_id */
        char *space = strchr(p, ' ');
        if (!space) return;
        size_t id_len = (size_t)(space - p);
        if (id_len >= sizeof(call_id)) id_len = sizeof(call_id) - 1;
        memcpy(call_id, p, id_len);
        call_id[id_len] = '\0';
        p = space + 1;
        while (*p == ' ') p++;

        /* Parse did */
        space = strchr(p, ' ');
        if (!space) return;
        id_len = (size_t)(space - p);
        if (id_len >= sizeof(did)) id_len = sizeof(did) - 1;
        memcpy(did, p, id_len);
        did[id_len] = '\0';
        p = space + 1;
        while (*p == ' ') p++;

        /* Parse cid */
        space = strchr(p, ' ');
        if (space) {
            id_len = (size_t)(space - p);
            if (id_len >= sizeof(cid)) id_len = sizeof(cid) - 1;
            memcpy(cid, p, id_len);
            cid[id_len] = '\0';
            p = space + 1;
            while (*p == ' ') p++;
        } else {
            strncpy(cid, p, sizeof(cid) - 1);
            p = "";
        }

        /* Parse remaining tokens as name=value tags */
        struct gw_tag_entry *tags = NULL;
        int tag_count = 0;
        while (*p) {
            while (*p == ' ') p++;
            if (!*p) break;
            char *tag_end = strchr(p, ' ');
            if (!tag_end) tag_end = p + strlen(p);
            char *eq = memchr(p, '=', tag_end - p);
            if (eq) {
                tag_count++;
                tags = realloc(tags, tag_count * sizeof(struct gw_tag_entry));
                struct gw_tag_entry *t = &tags[tag_count - 1];
                size_t name_len = eq - p;
                size_t val_len = tag_end - eq - 1;
                t->name = malloc(name_len + 1);
                memcpy(t->name, p, name_len);
                t->name[name_len] = '\0';
                t->value = malloc(val_len + 1);
                memcpy(t->value, eq + 1, val_len);
                t->value[val_len] = '\0';
            }
            p = tag_end;
        }

        pbx_handle_backbone_invite(bs->pbx, call_id, did, cid, tags, tag_count);

        /* Free parsed tags (deep-copied into call struct) */
        for (int i = 0; i < tag_count; i++) {
            free(tags[i].name);
            free(tags[i].value);
        }
        free(tags);
    } else if (strcmp(cmd, "ringing") == 0) {
        // Format: ringing <call_id> [<codec_tags>]
        char call_id[256] = {0};
        const char *p = arg;
        const char *space = strchr(p, ' ');
        size_t id_len = space ? (size_t)(space - p) : strlen(p);
        if (id_len >= sizeof(call_id)) id_len = sizeof(call_id) - 1;
        memcpy(call_id, p, id_len);
        call_id[id_len] = '\0';
        const char *tags = space ? space + 1 : "";
        pbx_on_backbone_ringing(bs->pbx, call_id, tags);
    } else if (strcmp(cmd, "answer") == 0) {
        // Format: answer <call_id> [<codec_tags>]
        char call_id[256] = {0};
        const char *p = arg;
        const char *space = strchr(p, ' ');
        size_t id_len = space ? (size_t)(space - p) : strlen(p);
        if (id_len >= sizeof(call_id)) id_len = sizeof(call_id) - 1;
        memcpy(call_id, p, id_len);
        call_id[id_len] = '\0';
        const char *tags = space ? space + 1 : "";
        pbx_on_backbone_answer(bs->pbx, call_id, tags);
    } else if (strcmp(cmd, "cancel") == 0) {
        pbx_on_backbone_cancel(bs->pbx, arg);
    } else if (strcmp(cmd, "media") == 0) {
        // Format: media <call_id> [<stream_id>] data:;hex,<hex>
        char call_id[256] = {0};
        int stream_id = -1;

        const char *p = arg;
        const char *space1 = strchr(p, ' ');
        if (!space1) return;
        size_t id_len = (size_t)(space1 - p);
        if (id_len >= sizeof(call_id)) return;
        memcpy(call_id, p, id_len);
        call_id[id_len] = '\0';

        /* after call_id: either "data:;hex,<hex>" or "<stream_id> data:;hex,<hex>" */
        p = space1 + 1;
        while (*p == ' ') p++;

        if (isdigit((unsigned char)*p)) {
            stream_id = atoi(p);
            while (isdigit((unsigned char)*p)) p++;
            while (*p == ' ') p++;
        }

        const char *hex_tag = "data:;";
        const char *found = strstr(p, hex_tag);
        if (!found) return;
        const char *hex_start = found + strlen(hex_tag);
        /* skip datatype;hex, */
        const char *hex_comma = strchr(hex_start, ',');
        if (!hex_comma) return;
        hex_start = hex_comma + 1;

        size_t hex_len = strlen(hex_start);
        uint8_t *raw = malloc(hex_len / 2 + 1);
        if (!raw) return;
        int raw_len = hex_decode(hex_start, raw, hex_len / 2 + 1);
        if (raw_len > 0) {
            pbx_on_backbone_media(bs->pbx, call_id, stream_id, raw, (size_t)raw_len);
        }
        free(raw);
    } else if (strcmp(cmd, "bye") == 0) {
        pbx_on_backbone_bye(bs->pbx, arg);
    } else {
        log_warn("backbone: unknown command '%s'", cmd);
    }
}

// ── send helpers ───────────────────────────────────────────────────────

static void backbone_send_line(struct backbone_state *s, const char *line, int len) {
    if (s->phase != BACKBONE_CONNECTED) return;
    if (s->fd < 0) return;
    send(s->fd, line, (size_t)len, 0);
}

void backbone_send_invite(struct backbone_state *s, const char *call_id,
                          const char *did, const char *cid,
                          const char *tags) {
    char line[1024];
    int len;
    if (tags && tags[0]) {
        len = snprintf(line, sizeof(line), "invite %s %s %s %s\n", call_id, did, cid, tags);
    } else {
        len = snprintf(line, sizeof(line), "invite %s %s %s\n", call_id, did, cid);
    }
    backbone_send_line(s, line, len);
}

void backbone_send_ringing(struct backbone_state *s, const char *call_id, const char *tags) {
    char line[4096];
    int len;
    if (tags && tags[0])
        len = snprintf(line, sizeof(line), "ringing %s %s\n", call_id, tags);
    else
        len = snprintf(line, sizeof(line), "ringing %s\n", call_id);
    backbone_send_line(s, line, len);
}

void backbone_send_answer(struct backbone_state *s, const char *call_id, const char *tags) {
    char line[4096];
    int len;
    if (tags && tags[0])
        len = snprintf(line, sizeof(line), "answer %s %s\n", call_id, tags);
    else
        len = snprintf(line, sizeof(line), "answer %s\n", call_id);
    backbone_send_line(s, line, len);
}

void backbone_send_cancel(struct backbone_state *s, const char *call_id) {
    char line[256];
    int len = snprintf(line, sizeof(line), "cancel %s\n", call_id);
    backbone_send_line(s, line, len);
}

void backbone_send_media(struct backbone_state *s, const char *call_id, int stream_id, const uint8_t *rtp, size_t len) {
    size_t hex_len = len * 2 + 1;
    char *hex_buf = malloc(hex_len);
    if (!hex_buf) return;
    hex_encode(rtp, len, hex_buf, hex_len);

    size_t line_cap = strlen(call_id) + hex_len + 48;
    char *line = malloc(line_cap);
    if (!line) { free(hex_buf); return; }
    int line_len;
    if (stream_id >= 0)
        line_len = snprintf(line, line_cap, "media %s %d data:;hex,%s\n", call_id, stream_id, hex_buf);
    else
        line_len = snprintf(line, line_cap, "media %s data:;hex,%s\n", call_id, hex_buf);

    backbone_send_line(s, line, line_len);
    free(line);
    free(hex_buf);
}

void backbone_send_bye(struct backbone_state *s, const char *call_id) {
    char line[256];
    int len = snprintf(line, sizeof(line), "bye %s\n", call_id);
    backbone_send_line(s, line, len);
}

// ── scheduler task ─────────────────────────────────────────────────────

static int backbone_task(int64_t timestamp, pt_task_t *task) {
    (void)timestamp;
    struct backbone_state *bs = task->udata;

    if (!bs->config->backbones) return SCHED_RUNNING;

    switch (bs->phase) {

    case BACKBONE_DISCONNECTED: {
        if (time(NULL) - bs->last_attempt < RECONNECT_INTERVAL) return SCHED_RUNNING;

        // Ensure we have a current target
        if (!bs->current) bs->current = bs->config->backbones;

        bs->last_attempt = time(NULL);

        // Parse host:port
        char host_buf[256] = {0};
        int port_val = 0;
        if (bs->current->host) strncpy(host_buf, bs->current->host, sizeof(host_buf) - 1);
        if (bs->current->port) port_val = atoi(bs->current->port);

        char port_buf[16];
        snprintf(port_buf, sizeof(port_buf), "%d", port_val);

        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(host_buf, port_buf, &hints, &res) != 0 || !res) {
            log_error("backbone: DNS resolution failed for %s:%s", host_buf, port_buf);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }

        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) {
            log_error("backbone: socket() failed: %s", strerror(errno));
            freeaddrinfo(res);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }

        // Non-blocking connect
        fcntl(fd, F_SETFL, O_NONBLOCK);

        int rc = connect(fd, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        if (rc < 0 && errno != EINPROGRESS) {
            log_debug("backbone: connect to %s:%d failed: %s",
                      host_buf, port_val, strerror(errno));
            close(fd);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }

        bs->fd = fd;
        bs->fail_index = 0;

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        log_info("backbone: connected to %s:%d, sending auth", host_buf, port_val);

        send_auth(bs);
        bs->phase = BACKBONE_WAIT_AUTH;
        bs->last_attempt = time(NULL);
        return SCHED_RUNNING;
    }

    case BACKBONE_WAIT_AUTH: {
        // Timeout check
        if (time(NULL) - bs->last_attempt > AUTH_TIMEOUT) {
            log_warn("backbone: auth timeout from %s", bs->current ? bs->current->address : "?");
            close_fd(bs);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }

        // Try to read
        char buf[1024];
        ssize_t n = recv(bs->fd, buf, sizeof(buf) - 1, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return SCHED_RUNNING;
            log_debug("backbone: recv error during auth: %s", strerror(errno));
            close_fd(bs);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }
        if (n == 0) {
            log_warn("backbone: connection closed during auth");
            close_fd(bs);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }

        buf[n] = '\0';

        // Check for "ok\n"
        if (strncmp(buf, "ok\n", 3) == 0 || strncmp(buf, "ok\r\n", 4) == 0) {
            log_info("backbone: authenticated to %s", bs->current ? bs->current->address : "?");
            bs->phase = BACKBONE_CONNECTED;

            // If there's leftover data after "ok\n", process it
            size_t consumed = (buf[2] == '\r') ? 4 : 3;
            if ((size_t)n > consumed) {
                // Append leftover to recv_buf
                size_t remaining = (size_t)n - consumed;
                if (remaining < sizeof(bs->recv_buf)) {
                    memcpy(bs->recv_buf, buf + consumed, remaining);
                    bs->recv_len = remaining;
                }
            }
            return SCHED_RUNNING;
        }

        // Anything else = auth failure
        log_warn("backbone: auth rejected by %s: %.*s",
                 bs->current ? bs->current->address : "?", (int)n, buf);
        close_fd(bs);
        advance_backbone(bs);
        return SCHED_RUNNING;
    }

    case BACKBONE_CONNECTED: {
        // Read data
        ssize_t n = recv(bs->fd,
                         bs->recv_buf + bs->recv_len,
                         sizeof(bs->recv_buf) - bs->recv_len - 1,
                         0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return SCHED_RUNNING;
            log_debug("backbone: recv error: %s", strerror(errno));
            close_fd(bs);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }
        if (n == 0) {
            log_info("backbone: connection closed by server");
            close_fd(bs);
            advance_backbone(bs);
            return SCHED_RUNNING;
        }

        bs->recv_len += (size_t)n;
        bs->recv_buf[bs->recv_len] = '\0';

        // Process complete lines
        char *start = bs->recv_buf;
        char *nl;
        while ((nl = strchr(start, '\n')) != NULL) {
            *nl = '\0';
            // Strip trailing \r
            char *cr = strchr(start, '\r');
            if (cr) *cr = '\0';
            if (strlen(start) > 0) {
                dispatch_line(bs, start);
            }
            start = nl + 1;
        }

        // Move remaining data to front of buffer
        size_t consumed = (size_t)(start - bs->recv_buf);
        size_t remaining = bs->recv_len - consumed;
        if (remaining > 0) {
            memmove(bs->recv_buf, start, remaining);
        }
        bs->recv_len = remaining;

        // Safety: if buffer is full with no newline, discard
        if (bs->recv_len >= sizeof(bs->recv_buf) - 1) {
            log_warn("backbone: line too long, discarding buffer");
            bs->recv_len = 0;
        }

        return SCHED_RUNNING;
    }

    }

    return SCHED_RUNNING;
}

// ── lifecycle ──────────────────────────────────────────────────────────

struct backbone_state *backbone_create(struct gw_config *cfg, struct pbx_state *pbx) {
    struct backbone_state *bs = calloc(1, sizeof(*bs));
    if (!bs) return NULL;

    bs->config     = cfg;
    bs->pbx        = pbx;
    bs->fd         = -1;
    bs->phase      = BACKBONE_DISCONNECTED;
    bs->current    = cfg->backbones;
    bs->last_attempt = 0;
    bs->fail_index = 0;

    bs->task = sched_create(backbone_task, bs);
    if (!bs->task) {
        free(bs);
        return NULL;
    }

    return bs;
}

void backbone_free(struct backbone_state *bs) {
    if (!bs) return;
    if (bs->task) sched_remove(bs->task);
    close_fd(bs);
    free(bs);
}
