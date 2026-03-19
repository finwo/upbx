#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "testutil.h"
#include "tap.h"

int main(void) {
    int pid = (int)getpid();
    char sock_a[256], sock_b[256];
    char conf_a[256], conf_b[256];

    snprintf(sock_a, sizeof(sock_a), "/tmp/upbx-test-A-%d.sock", pid);
    snprintf(sock_b, sizeof(sock_b), "/tmp/upbx-test-B-%d.sock", pid);
    snprintf(conf_a, sizeof(conf_a), "/tmp/upbx-test-A-%d.conf", pid);
    snprintf(conf_b, sizeof(conf_b), "/tmp/upbx-test-B-%d.conf", pid);

    /* Write config for Node A: alice + bob, peers with Node B */
    FILE *fa = fopen(conf_a, "w");
    if (!fa) { perror("fopen conf_a"); return 1; }
    fprintf(fa,
        "[upbx]\n"
        "cluster_secret = test-cluster-secret\n"
        "listen = unix://%s\n"
        "peer = unix://%s\n"
        "\n"
        "[user:alice]\n"
        "secret = alice-secret\n"
        "\n"
        "[user:bob]\n"
        "secret = bob-secret\n"
        "\n",
        sock_a, sock_b
    );
    fclose(fa);

    /* Write config for Node B: charlie, no outbound peer (A connects to B) */
    FILE *fb = fopen(conf_b, "w");
    if (!fb) { perror("fopen conf_b"); return 1; }
    fprintf(fb,
        "[upbx]\n"
        "cluster_secret = test-cluster-secret\n"
        "listen = unix://%s\n"
        "peer = unix://%s\n"
        "\n"
        "[user:charlie]\n"
        "secret = charlie-secret\n"
        "\n",
        sock_b, sock_a
    );
    fclose(fb);

    testutil_cleanup();
    atexit(testutil_cleanup);
    unlink(sock_a);
    unlink(sock_b);

    /* Start both daemons */
    if (testutil_daemon_start_idx(0, conf_a) < 0) {
        fprintf(stderr, "failed to start daemon A\n");
        return 1;
    }
    if (testutil_daemon_start_idx(1, conf_b) < 0) {
        fprintf(stderr, "failed to start daemon B\n");
        return 1;
    }

    if (testutil_wait_socket(sock_a, 5000) < 0) {
        fprintf(stderr, "daemon A failed to start\n");
        return 1;
    }
    if (testutil_wait_socket(sock_b, 5000) < 0) {
        fprintf(stderr, "daemon B failed to start\n");
        return 1;
    }

    /* Wait for peer connections to establish */
    usleep(1500000);

    /* Generate keypairs */
    uint8_t alice_pub[32], alice_priv[64];
    uint8_t bob_pub[32], bob_priv[64];
    uint8_t charlie_pub[32], charlie_priv[64];
    testutil_gen_keypair("alice-secret", "alice", alice_pub, alice_priv);
    testutil_gen_keypair("bob-secret", "bob", bob_pub, bob_priv);
    testutil_gen_keypair("charlie-secret", "charlie", charlie_pub, charlie_priv);

    /* Connect clients */
    test_client *alice   = testutil_client_connect(sock_a);
    test_client *bob     = testutil_client_connect(sock_a);
    test_client *charlie = testutil_client_connect(sock_b);
    ASSERT("alice connected", alice != NULL);
    ASSERT("bob connected", bob != NULL);
    ASSERT("charlie connected", charlie != NULL);
    if (!alice || !bob || !charlie) goto cleanup;

    /* Authenticate */
    ASSERT("alice auth", testutil_auth(alice, "alice", alice_pub, alice_priv) == 0);
    ASSERT("bob auth", testutil_auth(bob, "bob", bob_pub, bob_priv) == 0);
    ASSERT("charlie auth", testutil_auth(charlie, "charlie", charlie_pub, charlie_priv) == 0);

    /*
     * Test 1: Answered call with cancel broadcast
     *
     * Alice invites -> bob and charlie both get it
     * Bob and charlie both send ringing -> alice gets exactly one
     * Charlie answers -> alice gets answer, bob gets cancel
     */
    printf("# Test 1: answered call\n");

    testutil_client_send(alice, "invite call1 did1 cid1\n");

    /* Both bob and charlie should receive the invite */
    const char *line;
    line = testutil_client_recv_line(bob, 3000);
    ASSERT("bob got invite", line && strncmp(line, "invite call1", 12) == 0);

    line = testutil_client_recv_line(charlie, 3000);
    ASSERT("charlie got invite", line && strncmp(line, "invite call1", 12) == 0);

    /* Both send ringing */
    testutil_client_send(bob, "ringing call1\n");
    testutil_client_send(charlie, "ringing call1\n");

    /* Alice should receive exactly one ringing */
    line = testutil_client_recv_line(alice, 2000);
    ASSERT("alice got ringing", line && strncmp(line, "ringing call1", 13) == 0);

    /* Alice should NOT receive a second ringing (wait briefly) */
    line = testutil_client_recv_line(alice, 500);
    ASSERT("alice no second ringing", line == NULL);

    /* Charlie answers */
    testutil_client_send(charlie, "answer call1\n");

    /* Alice should receive answer */
    line = testutil_client_recv_line(alice, 2000);
    ASSERT("alice got answer", line && strncmp(line, "answer call1", 12) == 0);

    /* Bob should receive cancel */
    line = testutil_client_recv_line(bob, 2000);
    ASSERT("bob got cancel", line && strncmp(line, "cancel call1", 12) == 0);

    /* Media: alice -> charlie */
    testutil_client_send(alice, "media call1 data:;hex,deadbeef\n");
    line = testutil_client_recv_line(charlie, 2000);
    ASSERT("charlie got media", line && strstr(line, "deadbeef") != NULL);

    /* Media: charlie -> alice */
    testutil_client_send(charlie, "media call1 data:;hex,cafebabe\n");
    line = testutil_client_recv_line(alice, 2000);
    ASSERT("alice got media", line && strstr(line, "cafebabe") != NULL);

    /* Bye */
    testutil_client_send(alice, "bye call1\n");
    line = testutil_client_recv_line(charlie, 2000);
    ASSERT("charlie got bye", line && strncmp(line, "bye call1", 9) == 0);

    /*
     * Test 2: Caller cancel
     *
     * Alice invites -> bob and charlie get it
     * Alice cancels -> bob and charlie both get cancel
     */
    printf("# Test 2: caller cancel\n");

    testutil_client_send(alice, "invite call2 did2 cid2\n");

    line = testutil_client_recv_line(bob, 3000);
    ASSERT("bob got invite2", line && strncmp(line, "invite call2", 12) == 0);

    line = testutil_client_recv_line(charlie, 3000);
    ASSERT("charlie got invite2", line && strncmp(line, "invite call2", 12) == 0);

    testutil_client_send(alice, "cancel call2\n");

    line = testutil_client_recv_line(bob, 2000);
    ASSERT("bob got cancel2", line && strncmp(line, "cancel call2", 12) == 0);

    line = testutil_client_recv_line(charlie, 2000);
    ASSERT("charlie got cancel2", line && strncmp(line, "cancel call2", 12) == 0);

cleanup:
    testutil_client_close(alice);
    testutil_client_close(bob);
    testutil_client_close(charlie);
    testutil_daemon_stop_all();
    unlink(conf_a);
    unlink(conf_b);
    unlink(sock_a);
    unlink(sock_b);

    return tap_report();
}
