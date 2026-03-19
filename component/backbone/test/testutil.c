#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include "testutil.h"
#include "finwo/pbkdf2.h"
#include "orlp/ed25519.h"
#include "rxi/log.h"

#define PBKDF2_ITERATIONS 10000

static void derive_key(const char *secret, const char *username, uint8_t *private_key_out) {
    pbkdf2((uint8_t *)secret, strlen(secret),
           (uint8_t *)username, strlen(username),
           PBKDF2_ITERATIONS, PBKDF2_SHA256,
           private_key_out, 32);
}

static pid_t g_daemon_pids[MAX_DAEMONS];
static int g_daemon_count = 0;

void testutil_cleanup(void) {
    testutil_daemon_stop_all();
}

int testutil_daemon_start(const char *config_path) {
    return testutil_daemon_start_idx(0, config_path);
}

int testutil_daemon_start_idx(int idx, const char *config_path) {
    if (idx < 0 || idx >= MAX_DAEMONS) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execlp("./upbx-backbone", "./upbx-backbone", "daemon", "-c", config_path, NULL);
        _exit(1);
    }
    g_daemon_pids[idx] = pid;
    if (idx >= g_daemon_count) g_daemon_count = idx + 1;
    return 0;
}

void testutil_daemon_stop(void) {
    testutil_daemon_stop_idx(0);
}

void testutil_daemon_stop_idx(int idx) {
    if (idx < 0 || idx >= MAX_DAEMONS) return;
    if (g_daemon_pids[idx] > 0) {
        kill(g_daemon_pids[idx], SIGINT);
        /* Wait up to 5 seconds for daemon to exit */
        for (int i = 0; i < 50; i++) {
            int status;
            pid_t r = waitpid(g_daemon_pids[idx], &status, WNOHANG);
            if (r != 0) break;
            usleep(100000);
        }
        /* Force kill if still alive */
        kill(g_daemon_pids[idx], SIGKILL);
        waitpid(g_daemon_pids[idx], NULL, 0);
        g_daemon_pids[idx] = 0;
    }
}

void testutil_daemon_stop_all(void) {
    for (int i = 0; i < g_daemon_count; i++) {
        testutil_daemon_stop_idx(i);
    }
    g_daemon_count = 0;
}

int testutil_wait_socket(const char *path, int timeout_ms) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int deadline = (timeout_ms + 99) / 100;
    for (int i = 0; i < deadline; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(fd);
            return 0;
        }
        usleep(100000);
    }
    close(fd);
    return -1;
}

test_client *testutil_client_connect(const char *path) {
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return NULL;
    }
    test_client *c = calloc(1, sizeof(test_client));
    c->fd = fd;
    return c;
}

void testutil_client_close(test_client *c) {
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    free(c);
}

int testutil_client_send(test_client *c, const char *line) {
    size_t len = strlen(line);
    char buf[2048];
    if (len >= sizeof(buf)) return -1;
    memcpy(buf, line, len);
    if (len == 0 || buf[len-1] != '\n') {
        buf[len++] = '\n';
    }
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(c->fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

const char *testutil_client_recv_line(test_client *c, int timeout_ms) {
    c->recv_buf[c->recv_len] = '\0';
    char *newline = strchr(c->recv_buf, '\n');
    if (newline) {
        const char *result = c->recv_buf;
        size_t remaining = c->recv_len - (size_t)(newline - c->recv_buf) - 1;
        c->recv_len = remaining;
        if (remaining > 0) {
            memmove(c->recv_buf, newline + 1, remaining);
        }
        return result;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(c->fd, &fds);
    int ret = select(c->fd + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) return NULL;

    ssize_t n = recv(c->fd, c->recv_buf + c->recv_len, sizeof(c->recv_buf) - c->recv_len - 1, 0);
    if (n <= 0) return NULL;
    c->recv_len += (size_t)n;
    c->recv_buf[c->recv_len] = '\0';

    newline = strchr(c->recv_buf, '\n');
    if (!newline) return NULL;
    const char *result = c->recv_buf;
    size_t remaining = c->recv_len - (size_t)(newline - c->recv_buf) - 1;
    c->recv_len = remaining;
    if (remaining > 0) {
        memmove(c->recv_buf, newline + 1, remaining);
    }
    return result;
}

int testutil_hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        static const char hex[] = "0123456789abcdef";
        out[i*2] = hex[(in[i] >> 4) & 0xf];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[len*2] = '\0';
    return (int)(len * 2);
}

void testutil_gen_keypair(const char *secret, const char *username, uint8_t *pub, uint8_t *priv) {
    uint8_t seed[32];
    derive_key(secret, username, seed);
    ed25519_create_keypair(pub, priv, seed);
}

char *testutil_sign(const char *msg, size_t msg_len, const uint8_t *pub, const uint8_t *priv) {
    uint8_t sig[64];
    ed25519_sign(sig, (uint8_t *)msg, msg_len, pub, priv);
    static char hex[130];
    testutil_hex_encode(sig, 64, hex);
    return hex;
}

int testutil_auth(test_client *c, const char *username, const uint8_t *pub, const uint8_t *priv) {
    char auth_line[512];
    time_t nonce = time(NULL);
    char msg[128];
    snprintf(msg, sizeof(msg), "%s:%ld", username, (long)nonce);
    char *sig = testutil_sign(msg, strlen(msg), pub, priv);
    snprintf(auth_line, sizeof(auth_line), "auth %s:%ld %s\n", username, (long)nonce, sig);
    if (testutil_client_send(c, auth_line) < 0) return -1;
    const char *resp = testutil_client_recv_line(c, 2000);
    if (!resp) return -1;
    return 0;
}
