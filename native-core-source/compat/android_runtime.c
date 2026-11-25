/* Android lifecycle/underlay adapter. Apache-2.0. No protocol implementation. */
#include "homevpn_android.h"
#include "homevpn_rpc_auth.h"
#include "homevpn_legacy_instance.h"
#include "homevpn_frame.h"
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#define ENCRYPT_C
#include <Mayaqua/Mayaqua.h>
#undef ENCRYPT_C
#include <android/multinetwork.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
static int read_remote_hash(void);
static char admin_password[129];
/* Only androidsvc takes this process-lifetime lock. Keep the inode and FD;
 * unlinking a lock file would allow a second daemon to lock a different inode. */
static int daemon_lock_fd = -1;
static net_handle_t bound_underlay;

int homevpn_android_rootless_rpc_requested(void) {
    return getenv("HOMEVPN_ROOTLESS_RPC_PORT") != NULL;
}

unsigned int homevpn_android_rootless_rpc_port(void) {
    const char *port = getenv("HOMEVPN_ROOTLESS_RPC_PORT");
    if (port == NULL || port[0] == '\0') return 0;
    unsigned int value = 0;
    for (const char *p = port; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return 0;
        value = value * 10 + (unsigned int)(*p - '0');
        if (value > 65535) return 0;
    }
    return value >= 1024 ? value : 0;
}

static int hex_nibble(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int hex_byte(const char *encoded) {
    int high = hex_nibble((unsigned char)encoded[0]);
    int low = hex_nibble((unsigned char)encoded[1]);
    return high < 0 || low < 0 ? -1 : high * 16 + low;
}

int homevpn_android_frame_mac(unsigned char mac[6]) {
    const char *encoded = getenv("HOMEVPN_FRAME_MAC");
    if (encoded == NULL) return 0;
    if (strlen(encoded) != 12) return -1;
    unsigned char result[6];
    unsigned char any = 0;
    for (size_t i = 0; i < sizeof(result); ++i) {
        int value = hex_byte(encoded + 2 * i);
        if (value < 0) return -1;
        result[i] = (unsigned char)value;
        any |= result[i];
    }
    if (!any || (result[0] & 1)) return -1;
    memcpy(mac, result, sizeof(result));
    return 1;
}

int homevpn_android_decode_password(const char *encoded, char *password, size_t capacity) {
    size_t length = strlen(encoded);
    if ((length & 1) || length / 2 >= capacity) return 0;
    for (size_t i = 0; i < length / 2; ++i) {
        int value = hex_byte(encoded + 2 * i);
        if (value <= 0) return 0;
        password[i] = (char)(unsigned char)value;
    }
    password[length / 2] = '\0';
    return 1;
}

void homevpn_android_clear_password(char *password, size_t capacity) {
    OPENSSL_cleanse(password, capacity);
}

static int frame_tls_version(const char *name) {
    if (name == NULL || strcmp(name, "TLS") == 0 || strcmp(name, "DEFAULT") == 0) return 0;
    if (strcmp(name, "TLSv1") == 0) return TLS1_VERSION;
    if (strcmp(name, "TLSv1.1") == 0) return TLS1_1_VERSION;
    if (strcmp(name, "TLSv1.2") == 0) return TLS1_2_VERSION;
    if (strcmp(name, "TLSv1.3") == 0) return TLS1_3_VERSION;
    return -1;
}

static const SSL_CIPHER *find_standard_cipher(const STACK_OF(SSL_CIPHER) *known, const char *name) {
    for (int i = 0; i < sk_SSL_CIPHER_num(known); ++i) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(known, i);
        const char *standard = SSL_CIPHER_standard_name(cipher);
        if (standard != NULL && strcmp(standard, name) == 0) return cipher;
    }
    return NULL;
}

static int append_cipher(char *list, size_t capacity, const char *name) {
    size_t used = strlen(list);
    int written = snprintf(list + used, capacity - used, "%s%s", used ? ":" : "", name);
    return written >= 0 && (size_t)written < capacity - used;
}

int homevpn_android_frame_tls(SSL *ssl) {
    if (!homevpn_frame_active()) return 1;

    int version = frame_tls_version(getenv("HOMEVPN_FRAME_TLS_VERSION"));
    if (version < 0 || (version != 0 &&
        (!SSL_set_min_proto_version(ssl, version) || !SSL_set_max_proto_version(ssl, version))))
        return 0;

    const char *selection = getenv("HOMEVPN_FRAME_TLS_CIPHERS");
    if (selection == NULL) return 1;
    char names[4096], legacy[4096] = {0}, modern[4096] = {0};
    size_t length = strlen(selection);
    if (length == 0 || length >= sizeof(names) || selection[0] == ':' ||
        selection[length - 1] == ':' || strstr(selection, "::") != NULL)
        return 0;
    memcpy(names, selection, length + 1);

    SSL_CTX *catalog = SSL_CTX_new(TLS_client_method());
    if (catalog == NULL) return 0;
    int ok = SSL_CTX_set_cipher_list(catalog, "ALL");
    const STACK_OF(SSL_CIPHER) *known = SSL_CTX_get_ciphers(catalog);
    char *state = NULL;
    for (char *name = strtok_r(names, ":", &state); ok && name != NULL;
         name = strtok_r(NULL, ":", &state)) {
        const SSL_CIPHER *cipher = find_standard_cipher(known, name);
        if (cipher == NULL) {
            ok = 0;
        } else if (strcmp(SSL_CIPHER_get_version(cipher), "TLSv1.3") == 0) {
            ok = append_cipher(modern, sizeof(modern), SSL_CIPHER_get_name(cipher));
        } else {
            ok = append_cipher(legacy, sizeof(legacy), SSL_CIPHER_get_name(cipher));
        }
    }
    SSL_CTX_free(catalog);
    if (!ok || (version == TLS1_3_VERSION && modern[0] == '\0') ||
        (version != 0 && version < TLS1_3_VERSION && legacy[0] == '\0'))
        return 0;

    if (version == 0 && legacy[0] == '\0' && !SSL_set_min_proto_version(ssl, TLS1_3_VERSION))
        return 0;
    if (version == 0 && modern[0] == '\0' && !SSL_set_max_proto_version(ssl, TLS1_2_VERSION))
        return 0;
    return (legacy[0] == '\0' || SSL_set_cipher_list(ssl, legacy)) &&
        SSL_set_ciphersuites(ssl, modern);
}
/* Takes ownership of the verified private directory FD. Observe the official
 * pre-1.8.4 instance locks without taking, unlinking, or modifying any of them.
 * The new daemon lock remains held throughout this compatibility drain check. */
static int legacy_instances_drained(int directory) {
    DIR *entries = fdopendir(directory);
    if (entries == NULL) { close(directory); return -1; }
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (entry == NULL) { if (errno != 0) result = -1; break; }
        if (!homevpn_legacy_instance_name_valid(entry->d_name)) continue;
        int fd = openat(dirfd(entries), entry->d_name, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            /* The official owner unlinks its lock after releasing it. */
            if (errno == ENOENT) continue;
            result = -1; break;
        }
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); result = -1; break; }
        struct flock lock;
        memset(&lock, 0, sizeof(lock));
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        int queried;
        do { queried = fcntl(fd, F_GETLK, &lock); } while (queried != 0 && errno == EINTR);
        close(fd);
        if (queried != 0) { result = -1; break; }
        if (lock.l_type != F_UNLCK) { result = 1; break; }
    }
    if (closedir(entries) != 0 && result == 0) result = -1;
    return result;
}
static int lock_daemon_directory(void) {
    const char *path = getenv("HOMEVPN_DATA_DIR");
    if (path == NULL || path[0] != '/') return -1;
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return -1;
    struct stat directory_stat;
    if (fstat(directory, &directory_stat) != 0 || !S_ISDIR(directory_stat.st_mode) ||
            (directory_stat.st_mode & 0077) != 0 ||
            (homevpn_android_rootless_rpc_requested() && directory_stat.st_uid != geteuid())) {
        close(directory);
        return -1;
    }
    int fd = openat(directory, "androidsvc.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { close(directory); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
            (st.st_mode & 0777) != 0600 || (st.st_uid != geteuid() && st.st_uid != directory_stat.st_uid)) {
        close(fd); close(directory); return -1;
    }
    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    int result;
    do { result = fcntl(fd, F_SETLK, &lock); } while (result != 0 && errno == EINTR);
    if (result != 0) { close(fd); close(directory); return -1; }
    int drained = legacy_instances_drained(directory);
    if (drained != 0) {
        fputs(drained > 0 ?
            "homevpn: previous official client instance is still draining; retry required\n" :
            "homevpn: cannot safely inspect previous official client instance locks\n", stderr);
        close(fd);
        return -1;
    }
    daemon_lock_fd = fd;
    return 0;
}
static int read_secret(void) {
    const char *path = getenv("HOMEVPN_ADMIN_SECRET_FILE");
    if (path == NULL || path[0] != '/') return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 0077) != 0 ||
        st.st_size < 32 || st.st_size > 128 ||
        (homevpn_android_rootless_rpc_requested() && (st.st_uid != geteuid() || st.st_nlink != 1 ||
                                                   (st.st_mode & 0777) != 0600))) {
        close(fd);
        return -1;
    }
    ssize_t size = read(fd, admin_password, sizeof(admin_password) - 1);
    close(fd);
    if (size < 32 || size > 128) return -1;
    admin_password[size] = '\0';
    for (ssize_t i = 0; i < size; i++) {
        char c = admin_password[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return -1;
    }
    return 0;
}
static void *watch_owner(void *unused) {
    (void)unused;
    char buffer[32];
    for (;;) {
        ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (count > 0) continue;
        if (count < 0 && errno == EINTR) continue;
        kill(getpid(), SIGTERM);
        /* A blocked shutdown handler must not outlive its Android owner.  This
         * signals this process only; no PID files, killall or foreign clients. */
        sleep(15);
        kill(getpid(), SIGKILL);
        return NULL;
    }
}
int homevpn_android_prepare_daemon(void) {
    const char *frame_socket = getenv("HOMEVPN_FRAME_SOCKET");
    if ((frame_socket != NULL) != homevpn_android_rootless_rpc_requested() ||
        (frame_socket != NULL && (geteuid() == 0 || homevpn_android_rootless_rpc_port() == 0))) {
        fputs("homevpn: invalid rootless management configuration\n", stderr);
        return -1;
    }
    if (daemon_lock_fd < 0 && lock_daemon_directory() != 0) {
        fputs("homevpn: cannot claim private native daemon lock; another daemon may still be running\n", stderr);
        return -1;
    }
    if (frame_socket != NULL) {
        const char *remote = getenv("HOMEVPN_REMOTE_MANAGEMENT_ENABLED");
        unsigned char requested_mac[6];
        fprintf(stderr, "FRAME_CHILD_PID=%ld\n", (long)getpid());
        fflush(stderr);
        if ((remote != NULL && strcmp(remote, "1") == 0) ||
            homevpn_android_frame_mac(requested_mac) < 0 ||
            setenv("HOMEVPN_DEFER_STARTUP", "1", 1) != 0 ||
            homevpn_frame_prepare(frame_socket) != 0) {
            fputs("homevpn: cannot establish private userspace Ethernet channel\n", stderr);
            return -1;
        }
    }
    return homevpn_android_prepare(1);
}
int homevpn_android_prepare(int watch_stdin) {
    if (read_secret() != 0) { fputs("homevpn: private management secret unavailable\n", stderr); return -1; }
    if (read_remote_hash() != 0) { fputs("homevpn: valid private remote password hash required\n", stderr); return -1; }
    const char *handle = getenv("HOMEVPN_UNDERLYING_NETWORK_HANDLE");
    if (handle != NULL && handle[0] != '\0') {
        char *end = NULL;
        unsigned long long value = strtoull(handle, &end, 10);
        if (end == handle || *end != '\0' || value == 0 || android_setprocnetwork((net_handle_t)value) != 0) {
            fputs("homevpn: cannot bind the selected underlying network\n", stderr); return -1;
        }
        bound_underlay = (net_handle_t)value;
    }
    if (watch_stdin) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, watch_owner, NULL) != 0) return -1;
        pthread_detach(thread);
    }
    return 0;
}

/* Management authentication remains wire-compatible with official vpncmd:
 * twenty raw legacy SHA-0 bytes are password-equivalent credentials. Use a VPN or
 * trusted transport when enabling the opt-in remote listener. */
static unsigned char local_hash[20], remote_hash[20];
static char remote_hash_path[4096];
static int remote_allowed;
static pthread_mutex_t remote_lock = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int rpc_listen_scope;
static int read_remote_hash(void) {
    const char *enabled = getenv("HOMEVPN_REMOTE_MANAGEMENT_ENABLED");
    Hash(local_hash, admin_password, (UINT)strlen(admin_password), true);
    if (enabled == NULL || strcmp(enabled, "1") != 0) return 0;
    const char *path = getenv("HOMEVPN_REMOTE_PASSWORD_HASH_FILE");
    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(remote_hash_path)) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    unsigned char value[21];
    ssize_t count = read(fd, value, sizeof(value));
    int valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0077) == 0
        && st.st_size == 20 && count == 20 && homevpn_remote_hash_valid(value);
    close(fd);
    if (!valid) return -1;
    memcpy(remote_hash, value, 20);
    strcpy(remote_hash_path, path);
    remote_allowed = 1;
    return 0;
}
int homevpn_android_remote_allowed(void) { return remote_allowed; }
int homevpn_android_verify_rpc_hash(const unsigned char hash[20], int loopback, int remote_enabled) {
    int valid;
    pthread_mutex_lock(&remote_lock);
    valid = homevpn_rpc_authorized(hash, local_hash, remote_hash, loopback, remote_allowed, remote_enabled);
    pthread_mutex_unlock(&remote_lock);
    return valid;
}
int homevpn_android_set_remote_password(const char *password) {
    if (!remote_allowed || password == NULL || password[0] == '\0') return -1;
    /* The upstream RPC sentinel means retain the password, not eight stars. */
    if (strcmp(password, "********") == 0) return 0;
    unsigned char value[20];
    Hash(value, (void *)password, (UINT)strlen(password), true);
    if (!homevpn_remote_hash_valid(value)) return -1;
    pthread_mutex_lock(&remote_lock);
    int old = open(remote_hash_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat original;
    if (old < 0 || fstat(old, &original) != 0 || !S_ISREG(original.st_mode) || (original.st_mode & 0077) != 0 || original.st_size != 20) {
        if (old >= 0) close(old);
        pthread_mutex_unlock(&remote_lock); return -1;
    }
    char security_context[4096];
    ssize_t context_size = fgetxattr(old, "security.selinux", security_context, sizeof(security_context));
    if (context_size < 0 && errno != ENODATA && errno != ENOTSUP && errno != EOPNOTSUPP) {
        close(old); pthread_mutex_unlock(&remote_lock); return -1;
    }
    close(old);
    char temporary[sizeof(remote_hash_path) + 16];
    snprintf(temporary, sizeof(temporary), "%s.tmp.XXXXXX", remote_hash_path);
    int fd = mkstemp(temporary), result = -1;
    if (fd >= 0) {
        /* Preserve app ownership so the settings UI can still read/replace the
         * hash after this root process performs an atomic password update. */
        if (fchmod(fd, 0600) == 0 && fchown(fd, original.st_uid, original.st_gid) == 0
            && (context_size < 0 || fsetxattr(fd, "security.selinux", security_context, (size_t)context_size, 0) == 0)
            && write(fd, value, sizeof(value)) == sizeof(value) && fsync(fd) == 0
            && rename(temporary, remote_hash_path) == 0) {
            memcpy(remote_hash, value, sizeof(value));
            char directory[sizeof(remote_hash_path)];
            strcpy(directory, remote_hash_path);
            char *slash = strrchr(directory, '/');
            if (slash != NULL) {
                if (slash == directory) slash[1] = '\0'; else *slash = '\0';
                int parent = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
                if (parent >= 0) { result = fsync(parent) == 0 ? 0 : -1; close(parent); }
            }
        }
        close(fd);
        unlink(temporary);
    }
    pthread_mutex_unlock(&remote_lock);
    return result;
}
void homevpn_android_rpc_listen_scope(int enabled) { rpc_listen_scope = enabled; }
int homevpn_android_prepare_rpc_listener(int fd) {
    if (!rpc_listen_scope) return 0;
    if (homevpn_frame_active()) {
        if (remote_allowed) return -1;
        if (bound_underlay != 0 && android_setsocknetwork((net_handle_t)0, fd) != 0) {
            fputs("homevpn: cannot clear loopback listener underlying network\n", stderr);
            return -1;
        }
        return 0;
    }
    /* Clearing only accepted sockets is too late for SYN-ACK. Android netd
     * supplies ingress network marks; tcp_fwmark_accept preserves them from
     * the first SYN-ACK when the listening socket has no explicit mark. */
    if (remote_allowed) {
        char value[8] = {0};
        int sysctl = open("/proc/sys/net/ipv4/tcp_fwmark_accept", O_RDONLY | O_CLOEXEC);
        if (sysctl < 0) return -1;
        ssize_t count = read(sysctl, value, sizeof(value) - 1);
        close(sysctl);
        if (count < 1 || value[0] != '1') { fputs("homevpn: RPC ingress fwmark inheritance unavailable\n", stderr); return -1; }
    }
    uint32_t zero = 0;
    if (android_setsocknetwork((net_handle_t)0, fd) != 0 || setsockopt(fd, SOL_SOCKET, SO_MARK, &zero, sizeof(zero)) != 0) {
        fputs("homevpn: cannot clear RPC listener underlay binding\n", stderr); return -1;
    }
    return 0;
}
static int same_local_address(const struct sockaddr *local, const struct sockaddr *candidate, unsigned int index) {
    if (local->sa_family == AF_INET && candidate->sa_family == AF_INET)
        return ((const struct sockaddr_in *)local)->sin_addr.s_addr == ((const struct sockaddr_in *)candidate)->sin_addr.s_addr;
    if (local->sa_family == AF_INET6 && candidate->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)local, *b = (const struct sockaddr_in6 *)candidate;
        return memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0
            && (a->sin6_scope_id == 0 || a->sin6_scope_id == index);
    }
    return 0;
}
int homevpn_android_prepare_rpc_accepted(int fd) {
    struct sockaddr_storage local;
    socklen_t length = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &length) != 0) return -1;
    if (local.ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&local)->sin6_addr)) {
        struct in_addr ipv4;
        memcpy(&ipv4, &((struct sockaddr_in6 *)&local)->sin6_addr.s6_addr[12], sizeof(ipv4));
        memset(&local, 0, sizeof(local));
        ((struct sockaddr_in *)&local)->sin_family = AF_INET;
        ((struct sockaddr_in *)&local)->sin_addr = ipv4;
    }
    if (homevpn_frame_active()) {
        if (local.ss_family == AF_INET)
            return ntohl(((const struct sockaddr_in *)&local)->sin_addr.s_addr) == INADDR_LOOPBACK ? 0 : -1;
        if (local.ss_family == AF_INET6)
            return IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)&local)->sin6_addr) ? 0 : -1;
        return -1;
    }
    struct ifaddrs *addresses;
    if (getifaddrs(&addresses) != 0) return -1;
    char selected[IFNAMSIZ] = {0};
    int ambiguous = 0;
    for (struct ifaddrs *item = addresses; item != NULL; item = item->ifa_next) {
        if (item->ifa_addr == NULL || item->ifa_name == NULL || strlen(item->ifa_name) >= sizeof(selected)) continue;
        if (!same_local_address((struct sockaddr *)&local, item->ifa_addr, if_nametoindex(item->ifa_name))) continue;
        if (selected[0] != '\0' && strcmp(selected, item->ifa_name) != 0) { ambiguous = 1; break; }
        strcpy(selected, item->ifa_name);
    }
    freeifaddrs(addresses);
    if (ambiguous || selected[0] == '\0') { fputs("homevpn: RPC local interface cannot be determined\n", stderr); return -1; }
    uint32_t zero = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &zero, sizeof(zero)) != 0
        || setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, selected, strlen(selected) + 1) != 0) {
        fputs("homevpn: cannot bind RPC reply to its incoming interface\n", stderr); return -1;
    }
    return 0;
}

const char *homevpn_android_admin_password(void) { return admin_password; }
int homevpn_android_add_password_argument(int *argc, char ***argv) {
    /* /IN is the command input. stdin is an exclusive owner-lifetime pipe. */
    if (homevpn_android_prepare(1) != 0) return -1;
    char **expanded = calloc((size_t)*argc + 2, sizeof(char *));
    char *argument = malloc(strlen(admin_password) + sizeof("/PASSWORD:"));
    if (expanded == NULL || argument == NULL) { free(expanded); free(argument); return -1; }
    strcpy(argument, "/PASSWORD:"); strcat(argument, admin_password);
    for (int i = 0; i < *argc; i++) expanded[i] = (*argv)[i];
    expanded[*argc] = argument;
    *argv = expanded; (*argc)++;
    return 0;
}
