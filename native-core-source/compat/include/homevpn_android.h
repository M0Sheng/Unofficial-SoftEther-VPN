#ifndef HOMEVPN_ANDROID_H
#define HOMEVPN_ANDROID_H
#include <stddef.h>
typedef struct ssl_st SSL;
int homevpn_android_prepare(int watch_stdin);
int homevpn_android_prepare_daemon(void);
const char *homevpn_android_admin_password(void);
int homevpn_android_add_password_argument(int *argc, char ***argv);
int homevpn_android_remote_allowed(void);
int homevpn_android_verify_rpc_hash(const unsigned char hash[20], int loopback, int remote_enabled);
int homevpn_android_set_remote_password(const char *password);
void homevpn_android_rpc_listen_scope(int enabled);
int homevpn_android_prepare_rpc_listener(int socket_fd);
int homevpn_android_prepare_rpc_accepted(int socket_fd);
int homevpn_android_rootless_rpc_requested(void);
unsigned int homevpn_android_rootless_rpc_port(void);
int homevpn_android_frame_mac(unsigned char mac[6]);
int homevpn_android_decode_password(const char *encoded, char *password, size_t capacity);
void homevpn_android_clear_password(char *password, size_t capacity);
int homevpn_android_frame_tls(SSL *ssl);
#endif
