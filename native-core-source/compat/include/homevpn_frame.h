#ifndef HOMEVPN_FRAME_H
#define HOMEVPN_FRAME_H

#include <stddef.h>

#define HOMEVPN_MIN_FRAME 14
#define HOMEVPN_MAX_FRAME 1600

enum homevpn_frame_result {
    HOMEVPN_FRAME_FAILED = -1,
    HOMEVPN_FRAME_IDLE = 0,
    HOMEVPN_FRAME_DELIVERED = 1,
};

/* The owner holds a private control listener, authenticates the child and
 * sends one end of a connected AF_UNIX SOCK_SEQPACKET pair with marker F. */
int homevpn_frame_prepare(const char *abstract_name);
int homevpn_frame_active(void);
int homevpn_frame_dup(void);
enum homevpn_frame_result homevpn_frame_read(int fd, void *buffer, size_t *length);
enum homevpn_frame_result homevpn_frame_write(int fd, const void *buffer, size_t length);

static inline int homevpn_frame_size_valid(size_t length) {
    return length >= HOMEVPN_MIN_FRAME && length <= HOMEVPN_MAX_FRAME;
}

static inline int homevpn_frame_name_valid(const char *name, size_t capacity) {
    if (name == NULL) return 0;
    for (size_t i = 0; i < capacity; i++) {
        char c = name[i];
        if (c == '\0') return i > 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 0;
}

static inline int homevpn_frame_peer_valid(unsigned int uid, int pid,
                                           unsigned int owner_uid, int owner_pid) {
    return owner_uid != 0 && owner_pid > 1 && uid == owner_uid && pid == owner_pid;
}

#endif
