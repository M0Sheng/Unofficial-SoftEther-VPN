/* Pure management authentication policy shared by Android runtime and host tests.
 * Apache-2.0. Credential comparison consumes all twenty legacy SHA-0 bytes. */
#ifndef HOMEVPN_RPC_AUTH_H
#define HOMEVPN_RPC_AUTH_H
static const unsigned char homevpn_empty_sha0[20] = {
    0xf9,0x6c,0xea,0x19,0x8a,0xd1,0xdd,0x56,0x17,0xac,
    0x08,0x4a,0x3d,0x92,0xc6,0x10,0x77,0x08,0xc0,0xef
};
static int homevpn_hash_equal(const unsigned char *a, const unsigned char *b) {
    unsigned int different = 0;
    for (unsigned int i = 0; i < 20; i++) different |= a[i] ^ b[i];
    return different == 0;
}
static int homevpn_remote_hash_valid(const unsigned char *hash) {
    static const unsigned char zero[20] = {0};
    return !homevpn_hash_equal(hash, zero) && !homevpn_hash_equal(hash, homevpn_empty_sha0);
}
static int homevpn_rpc_authorized(const unsigned char presented[20], const unsigned char local[20],
    const unsigned char remote[20], int loopback, int allowed, int enabled) {
    if (loopback) return homevpn_remote_hash_valid(local) && homevpn_hash_equal(presented, local);
    return allowed && enabled && homevpn_remote_hash_valid(remote) && homevpn_hash_equal(presented, remote);
}
#endif

