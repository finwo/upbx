#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include "testutil.h"
#include "tap.h"

static char socket_path[256];
static uint8_t alice_pub[32], alice_priv[64];
static uint8_t bob_pub[32], bob_priv[64];
static uint8_t charlie_pub[32], charlie_priv[64];

static test_client *connect_and_auth(const char *user, uint8_t *pub, uint8_t *priv) {
    test_client *c = testutil_client_connect(socket_path);
    if (!c) return NULL;
    if (testutil_auth(c, user, pub, priv) < 0) {
        testutil_client_close(c);
        return NULL;
    }
    return c;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    char config_path[256];
    int pid = (int)getpid();

    snprintf(config_path, sizeof(config_path), "/tmp/upbx-edge-%d.conf", pid);
    snprintf(socket_path, sizeof(socket_path), "/tmp/upbx-edge-%d.sock", pid);

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
        "\n"
        "[user:charlie]\n"
        "secret = charlie-secret\n"
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

    testutil_gen_keypair("alice-secret", "alice", alice_pub, alice_priv);
    testutil_gen_keypair("bob-secret", "bob", bob_pub, bob_priv);
    testutil_gen_keypair("charlie-secret", "charlie", charlie_pub, charlie_priv);

    const char *line;

    /*
     * Test 1: Unauthenticated commands are dropped
     */
    printf("# Test: unauthenticated commands dropped\n");
    {
        test_client *unauth = testutil_client_connect(socket_path);
        ASSERT("unauth connected", unauth != NULL);

        /* Send invite without auth -- should be silently dropped */
        testutil_client_send(unauth, "invite callX did cid\n");

        /* Connect an authed client to verify nothing was forwarded */
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        ASSERT("alice authed", alice != NULL);

        line = testutil_client_recv_line(alice, 500);
        ASSERT("alice got nothing from unauth invite", line == NULL);

        testutil_client_close(unauth);
        testutil_client_close(alice);
    }

    /*
     * Test 2: Invite deduplication
     */
    printf("# Test: invite dedup\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        test_client *charlie = connect_and_auth("charlie", charlie_pub, charlie_priv);
        ASSERT("all connected for dedup", alice && bob && charlie);

        /* Alice sends invite */
        testutil_client_send(alice, "invite dedup1 did cid\n");
        line = testutil_client_recv_line(bob, 2000);
        ASSERT("bob got invite dedup1", line && strncmp(line, "invite dedup1", 13) == 0);
        line = testutil_client_recv_line(charlie, 2000);
        ASSERT("charlie got invite dedup1", line && strncmp(line, "invite dedup1", 13) == 0);

        /* Bob tries to send the same call-id invite -- should be dropped entirely */
        testutil_client_send(bob, "invite dedup1 did2 cid2\n");

        /* Neither alice nor charlie should receive the duplicate */
        line = testutil_client_recv_line(alice, 500);
        ASSERT("alice no dup invite", line == NULL);
        line = testutil_client_recv_line(charlie, 500);
        ASSERT("charlie no dup invite", line == NULL);

        /* Clean up the call */
        testutil_client_send(alice, "cancel dedup1\n");
        /* Drain the cancel messages */
        testutil_client_recv_line(bob, 1000);
        testutil_client_recv_line(charlie, 1000);

        testutil_client_close(alice);
        testutil_client_close(bob);
        testutil_client_close(charlie);
    }

    /*
     * Test 3: Answer for unknown call-id is dropped
     */
    printf("# Test: answer unknown call dropped\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        ASSERT("connected for unknown answer", alice && bob);

        testutil_client_send(bob, "answer nonexistent\n");

        /* Alice should receive nothing */
        line = testutil_client_recv_line(alice, 500);
        ASSERT("alice got nothing from unknown answer", line == NULL);

        testutil_client_close(alice);
        testutil_client_close(bob);
    }

    /*
     * Test 4: Double-pickup sends bye to late answerer
     */
    printf("# Test: double-pickup bye\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        test_client *charlie = connect_and_auth("charlie", charlie_pub, charlie_priv);
        ASSERT("connected for double-pickup", alice && bob && charlie);

        testutil_client_send(alice, "invite dpick1 did cid\n");
        testutil_client_recv_line(bob, 2000);    /* bob gets invite */
        testutil_client_recv_line(charlie, 2000); /* charlie gets invite */

        /* Bob sends ringing first — collapses the call, charlie gets cancel */
        testutil_client_send(bob, "ringing dpick1\n");
        line = testutil_client_recv_line(alice, 2000);
        ASSERT("alice got ringing", line && strncmp(line, "ringing dpick1", 14) == 0);

        /* Charlie gets cancel (from ringing collapse) */
        line = testutil_client_recv_line(charlie, 2000);
        ASSERT("charlie got cancel from ringing", line && strncmp(line, "cancel dpick1", 13) == 0);

        /* Bob answers first (selected callee) */
        testutil_client_send(bob, "answer dpick1\n");
        line = testutil_client_recv_line(alice, 2000);
        ASSERT("alice got answer from bob", line && strncmp(line, "answer dpick1", 13) == 0);

        /* Charlie tries to answer late -- should get bye back */
        testutil_client_send(charlie, "answer dpick1\n");
        line = testutil_client_recv_line(charlie, 2000);
        ASSERT("charlie got bye for late answer", line && strncmp(line, "bye dpick1", 10) == 0);

        /* Alice should NOT receive a second answer */
        line = testutil_client_recv_line(alice, 500);
        ASSERT("alice no second answer", line == NULL);

        /* Clean up */
        testutil_client_send(alice, "bye dpick1\n");
        testutil_client_recv_line(bob, 1000);

        testutil_client_close(alice);
        testutil_client_close(bob);
        testutil_client_close(charlie);
    }

    /*
     * Test 5: Cancel for unknown call-id is dropped
     */
    printf("# Test: cancel unknown call dropped\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        ASSERT("connected for unknown cancel", alice && bob);

        testutil_client_send(alice, "cancel nonexistent2\n");

        line = testutil_client_recv_line(bob, 500);
        ASSERT("bob got nothing from unknown cancel", line == NULL);

        testutil_client_close(alice);
        testutil_client_close(bob);
    }

    /*
     * Test 6: Cancel for ringing/active call is dropped
     */
    printf("# Test: cancel for ringing/active call dropped\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        ASSERT("connected for active cancel", alice && bob);

        testutil_client_send(alice, "invite active1 did cid\n");
        testutil_client_recv_line(bob, 2000); /* bob gets invite */

        /* Bob sends ringing — collapses the call */
        testutil_client_send(bob, "ringing active1\n");
        line = testutil_client_recv_line(alice, 2000);
        ASSERT("alice got ringing active1", line && strncmp(line, "ringing active1", 15) == 0);

        /* Cancel after ringing should be dropped */
        testutil_client_send(alice, "cancel active1\n");

        /* Bob should NOT receive cancel (call is ringing) */
        line = testutil_client_recv_line(bob, 500);
        ASSERT("bob no cancel for ringing call", line == NULL);

        /* Media should still work after answer */
        testutil_client_send(bob, "answer active1\n");
        line = testutil_client_recv_line(alice, 2000);
        ASSERT("alice got answer active1", line && strncmp(line, "answer active1", 14) == 0);

        testutil_client_send(alice, "media active1 data:;hex,aabb\n");
        line = testutil_client_recv_line(bob, 2000);
        ASSERT("bob still gets media after failed cancel", line && strstr(line, "aabb") != NULL);

        /* Clean up */
        testutil_client_send(alice, "bye active1\n");
        testutil_client_recv_line(bob, 1000);

        testutil_client_close(alice);
        testutil_client_close(bob);
    }

    /*
     * Test 7: Bye for unknown call-id is dropped
     */
    printf("# Test: bye unknown call dropped\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        ASSERT("connected for unknown bye", alice && bob);

        testutil_client_send(alice, "bye nonexistent3\n");

        line = testutil_client_recv_line(bob, 500);
        ASSERT("bob got nothing from unknown bye", line == NULL);

        testutil_client_close(alice);
        testutil_client_close(bob);
    }

    /*
     * Test 8: Ringing dedup -- only first ringing forwarded to caller
     */
    printf("# Test: ringing dedup\n");
    {
        test_client *alice = connect_and_auth("alice", alice_pub, alice_priv);
        test_client *bob = connect_and_auth("bob", bob_pub, bob_priv);
        test_client *charlie = connect_and_auth("charlie", charlie_pub, charlie_priv);
        ASSERT("connected for ringing dedup", alice && bob && charlie);

        testutil_client_send(alice, "invite ring1 did cid\n");
        testutil_client_recv_line(bob, 2000);    /* bob gets invite */
        testutil_client_recv_line(charlie, 2000); /* charlie gets invite */

        /* Both send ringing — first one collapses the call */
        testutil_client_send(bob, "ringing ring1\n");

        /* Alice should get ringing from bob */
        line = testutil_client_recv_line(alice, 2000);
        ASSERT("alice got first ringing", line && strncmp(line, "ringing ring1", 13) == 0);

        /* Charlie gets cancel (from ringing collapse) */
        line = testutil_client_recv_line(charlie, 2000);
        ASSERT("charlie got cancel from ringing", line && strncmp(line, "cancel ring1", 12) == 0);

        /* Charlie's ringing is ignored (already collapsed) */
        testutil_client_send(charlie, "ringing ring1\n");

        line = testutil_client_recv_line(alice, 500);
        ASSERT("alice no second ringing", line == NULL);

        /* Clean up with bye (cancel is ignored after ringing) */
        testutil_client_send(alice, "bye ring1\n");
        testutil_client_recv_line(bob, 1000);

        testutil_client_close(alice);
        testutil_client_close(bob);
        testutil_client_close(charlie);
    }

    /*
     * Test 9: Auth timeout closes connection
     */
    printf("# Test: auth timeout\n");
    {
        test_client *unauth = testutil_client_connect(socket_path);
        ASSERT("unauth connected for timeout", unauth != NULL);

        /* Wait for auth timeout (10 seconds) + margin */
        sleep(12);

        /* Try to send -- should fail because connection was closed */
        int ret = testutil_client_send(unauth, "ping\n");
        line = testutil_client_recv_line(unauth, 500);
        ASSERT("auth timeout: no response", ret < 0 || line == NULL);

        testutil_client_close(unauth);
    }

    /* Cleanup */
    testutil_daemon_stop();
    unlink(config_path);
    unlink(socket_path);

    return tap_report();
}
