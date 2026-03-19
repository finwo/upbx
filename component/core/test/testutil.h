#ifndef UPBX_TESTUTIL_H
#define UPBX_TESTUTIL_H

#include <sys/socket.h>
#include <stdint.h>

#define MAX_DAEMONS 8

typedef struct {
    int fd;
    char recv_buf[4096];
    size_t recv_len;
} test_client;

void testutil_cleanup(void);
int testutil_daemon_start(const char *config_path);
int testutil_daemon_start_idx(int idx, const char *config_path);
void testutil_daemon_stop(void);
void testutil_daemon_stop_idx(int idx);
void testutil_daemon_stop_all(void);
int testutil_wait_socket(const char *path, int timeout_ms);
test_client *testutil_client_connect(const char *path);
void testutil_client_close(test_client *c);
int testutil_client_send(test_client *c, const char *line);
const char *testutil_client_recv_line(test_client *c, int timeout_ms);
int testutil_hex_encode(const uint8_t *in, size_t len, char *out);
void testutil_gen_keypair(const char *secret, const char *username, uint8_t *pub, uint8_t *priv);
char *testutil_sign(const char *msg, size_t msg_len, const uint8_t *pub, const uint8_t *priv);
int testutil_auth(test_client *c, const char *username, const uint8_t *pub, const uint8_t *priv);

#endif
