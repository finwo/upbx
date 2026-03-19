#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include "testutil.h"
#include "tap.h"

int main(void) {
    char config_path[256];
    char socket_path[256];

    snprintf(config_path, sizeof(config_path), "/tmp/upbx-test-%d.conf", (int)getpid());
    snprintf(socket_path, sizeof(socket_path), "/tmp/upbx-test-%d.sock", (int)getpid());

    FILE *f = fopen(config_path, "w");
    if (!f) { perror("fopen config"); return 1; }
    fprintf(f,
        "[upbx]\n"
        "cluster_secret = test-cluster-secret\n"
        "listen = unix://%s\n"
        "\n"
        "[user:alice]\n"
        "secret = alice-secret\n"
        "\n"
        "[user:bob]\n"
        "secret = bob-secret\n"
        "\n",
        socket_path
    );
    fclose(f);

    testutil_cleanup();
    atexit(testutil_cleanup);
    unlink(socket_path);

    if (testutil_daemon_start(config_path) < 0) {
        fprintf(stderr, "failed to start daemon\n");
        return 1;
    }

    if (testutil_wait_socket(socket_path, 5000) < 0) {
        fprintf(stderr, "daemon failed to start\n");
        return 1;
    }

    uint8_t alice_pub[32], alice_priv[64];
    uint8_t bob_pub[32], bob_priv[64];
    testutil_gen_keypair("alice-secret", "alice", alice_pub, alice_priv);
    testutil_gen_keypair("bob-secret", "bob", bob_pub, bob_priv);

    test_client *alice = testutil_client_connect(socket_path);
    test_client *bob = testutil_client_connect(socket_path);
    if (!alice || !bob) {
        fprintf(stderr, "failed to connect clients\n");
        return 1;
    }

    if (testutil_auth(alice, "alice", alice_pub, alice_priv) < 0) {
        fprintf(stderr, "alice auth failed\n");
        return 1;
    }
    if (testutil_auth(bob, "bob", bob_pub, bob_priv) < 0) {
        fprintf(stderr, "bob auth failed\n");
        return 1;
    }

    testutil_client_send(alice, "invite call1 bob alice\n");

    const char *inv = testutil_client_recv_line(bob, 2000);
    if (!inv || strncmp(inv, "invite call1 bob alice", 20) != 0) {
        fprintf(stderr, "expected invite, got: %s\n", inv ? inv : "(null)");
        return 1;
    }

    /* Callee (bob) sends ringing, caller (alice) receives it */
    testutil_client_send(bob, "ringing call1\n");

    const char *ring = testutil_client_recv_line(alice, 2000);
    if (!ring || strncmp(ring, "ringing call1", 13) != 0) {
        fprintf(stderr, "expected ringing, got: %s\n", ring ? ring : "(null)");
        return 1;
    }

    testutil_client_send(bob, "answer call1\n");

    const char *ans = testutil_client_recv_line(alice, 2000);
    if (!ans || strncmp(ans, "answer call1", 12) != 0) {
        fprintf(stderr, "expected answer, got: %s\n", ans ? ans : "(null)");
        return 1;
    }

    uint8_t media[] = {0x01, 0x02, 0x03, 0x04};
    char hex_buf[16];
    testutil_hex_encode(media, 4, hex_buf);
    char media_line[256];
    snprintf(media_line, sizeof(media_line), "media call1 data:;hex,%s\n", hex_buf);
    testutil_client_send(alice, media_line);

    const char *rcv = testutil_client_recv_line(bob, 2000);
    if (!rcv || strncmp(rcv, "media call1 data:;hex,01020304", 26) != 0) {
        fprintf(stderr, "expected media, got: %s\n", rcv ? rcv : "(null)");
        return 1;
    }

    testutil_client_send(bob, "bye call1\n");

    const char *bye = testutil_client_recv_line(alice, 2000);
    if (!bye || strncmp(bye, "bye call1", 8) != 0) {
        fprintf(stderr, "expected bye, got: %s\n", bye ? bye : "(null)");
        return 1;
    }

    testutil_client_close(alice);
    testutil_client_close(bob);

    testutil_daemon_stop();

    unlink(config_path);

    printf("ok 1 - same_node test passed\n");
    return 0;
}
