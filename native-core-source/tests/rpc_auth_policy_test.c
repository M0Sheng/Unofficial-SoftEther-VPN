/* Runs the exact C policy included by android_runtime.c, with no OS/crypto mocks.
 * Host test only: does not exercise Android socket routing or file persistence. */
#include "homevpn_rpc_auth.h"
static int checks;
#define CHECK(condition) do { checks++; if (!(condition)) return checks; } while (0)
int mainCRTStartup(void) {
    unsigned char local[20], remote[20], wrong[20], zero[20];
    for (int i = 0; i < 20; i++) { local[i] = 0x31; remote[i] = 0x42; wrong[i] = 0x53; zero[i] = 0; }
    for (int loopback = 0; loopback <= 1; loopback++)
        for (int allowed = 0; allowed <= 1; allowed++)
            for (int enabled = 0; enabled <= 1; enabled++) {
                CHECK(homevpn_rpc_authorized(local, local, remote, loopback, allowed, enabled) == loopback);
                CHECK(homevpn_rpc_authorized(remote, local, remote, loopback, allowed, enabled) == (!loopback && allowed && enabled));
                CHECK(!homevpn_rpc_authorized(wrong, local, remote, loopback, allowed, enabled));
            }
    CHECK(homevpn_remote_hash_valid(local));
    CHECK(homevpn_remote_hash_valid(remote));
    CHECK(!homevpn_remote_hash_valid(zero));
    CHECK(!homevpn_remote_hash_valid(homevpn_empty_sha0));
    CHECK(!homevpn_rpc_authorized(zero, local, zero, 0, 1, 1));
    CHECK(!homevpn_rpc_authorized(homevpn_empty_sha0, local, homevpn_empty_sha0, 0, 1, 1));
    return checks == 30 ? 0 : 101;
}

