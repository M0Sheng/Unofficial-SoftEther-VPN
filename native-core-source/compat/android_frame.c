/* Android userspace Ethernet frame adapter for the official SoftEther core. */
#define _GNU_SOURCE
#include "homevpn_frame.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int endpoint = -1;

static int owner_matches(int fd, uid_t uid, pid_t pid) {
    struct ucred peer;
    socklen_t size = sizeof(peer);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 &&
           size == sizeof(peer) && homevpn_frame_peer_valid(peer.uid, peer.pid, uid, pid);
}

static int frame_endpoint_valid(int fd, uid_t uid, pid_t pid) {
    int type = 0;
    socklen_t type_size = sizeof(type);
    struct sockaddr_un peer;
    socklen_t peer_size = sizeof(peer);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0 &&
           type_size == sizeof(type) && type == SOCK_SEQPACKET &&
           getpeername(fd, (struct sockaddr *)&peer, &peer_size) == 0 &&
           peer_size >= offsetof(struct sockaddr_un, sun_path) &&
           peer.sun_family == AF_UNIX && owner_matches(fd, uid, pid);
}

static int receive_endpoint(int control, uid_t uid, pid_t pid) {
    char marker = 0;
    struct iovec payload = { &marker, sizeof(marker) };
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int) * 4)];
    } ancillary;
    struct msghdr message = {
        .msg_iov = &payload,
        .msg_iovlen = 1,
        .msg_control = ancillary.bytes,
        .msg_controllen = sizeof(ancillary.bytes),
    };
    ssize_t count = recvmsg(control, &message, MSG_CMSG_CLOEXEC);
    if (count < 0) return -1;

    int received = -1;
    unsigned int descriptors = 0;
    for (struct cmsghdr *item = CMSG_FIRSTHDR(&message); item != NULL;
         item = CMSG_NXTHDR(&message, item)) {
        if (item->cmsg_level != SOL_SOCKET || item->cmsg_type != SCM_RIGHTS ||
            item->cmsg_len < CMSG_LEN(0))
            continue;

        size_t descriptor_count = (item->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t index = 0; index < descriptor_count; index++) {
            int descriptor;
            memcpy(&descriptor, CMSG_DATA(item) + index * sizeof(descriptor), sizeof(descriptor));
            if (descriptors++ == 0) received = descriptor;
            else close(descriptor);
        }
    }

    if (received < 0) return -1;
    if (count != 1 || marker != 'F' || descriptors != 1 ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        !frame_endpoint_valid(received, uid, pid)) {
        close(received);
        return -1;
    }
    int flags = fcntl(received, F_GETFL);
    if (flags < 0 || fcntl(received, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(received);
        return -1;
    }
    return received;
}

int homevpn_frame_prepare(const char *abstract_name) {
    if (abstract_name == NULL) return 0;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    uid_t owner_uid = getuid();
    pid_t owner_pid = getppid();
    if (endpoint >= 0 || owner_uid == 0 || owner_uid != geteuid() || owner_pid <= 1 ||
        !homevpn_frame_name_valid(abstract_name, sizeof(address.sun_path) - 1))
        return -1;
    size_t name_length = strlen(abstract_name);
    memcpy(address.sun_path + 1, abstract_name, name_length);
    socklen_t address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_length);
    int control = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (control < 0) return -1;
    if (connect(control, (struct sockaddr *)&address, address_length) == 0 &&
        owner_matches(control, owner_uid, owner_pid)) {
        struct pollfd readable = { .fd = control, .events = POLLIN };
        if (poll(&readable, 1, 5000) == 1 && (readable.revents & POLLIN)) {
            endpoint = receive_endpoint(control, owner_uid, owner_pid);
        }
    }
    close(control);
    return endpoint >= 0 ? 0 : -1;
}

int homevpn_frame_active(void) {
    return endpoint >= 0;
}

int homevpn_frame_dup(void) {
    return fcntl(endpoint, F_DUPFD_CLOEXEC, 0);
}

enum homevpn_frame_result homevpn_frame_read(int fd, void *buffer, size_t *length) {
    *length = 0;
    struct iovec payload = { buffer, HOMEVPN_MAX_FRAME };
    struct msghdr message = { .msg_iov = &payload, .msg_iovlen = 1 };
    ssize_t count;
    do { count = recvmsg(fd, &message, MSG_DONTWAIT); } while (count < 0 && errno == EINTR);
    if (count == 0) return HOMEVPN_FRAME_FAILED;
    if (count < 0) return errno == EAGAIN || errno == EWOULDBLOCK ?
        HOMEVPN_FRAME_IDLE : HOMEVPN_FRAME_FAILED;
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || !homevpn_frame_size_valid((size_t)count))
        return HOMEVPN_FRAME_IDLE;
    *length = (size_t)count;
    return HOMEVPN_FRAME_DELIVERED;
}

enum homevpn_frame_result homevpn_frame_write(int fd, const void *buffer, size_t length) {
    if (!homevpn_frame_size_valid(length)) return HOMEVPN_FRAME_IDLE;
    ssize_t count;
    do { count = send(fd, buffer, length, MSG_NOSIGNAL | MSG_DONTWAIT); } while (count < 0 && errno == EINTR);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return HOMEVPN_FRAME_IDLE;
    return count == (ssize_t)length ? HOMEVPN_FRAME_DELIVERED : HOMEVPN_FRAME_FAILED;
}
