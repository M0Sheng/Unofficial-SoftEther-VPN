#include <errno.h>
#include <jni.h>
#include <stddef.h>
#include <stdint.h>

typedef struct TunSession TunSession;

extern TunSession *softether_tun_create(const uint8_t *options, size_t length, uint64_t now);
extern jint softether_tun_step(TunSession *session, jint frame_fd, jint tun_fd, jint mtu, jint reset,
    uint64_t now, uint8_t *status, size_t capacity);
extern void softether_tun_stop(TunSession *session, jint frame_fd, uint64_t now);

JNIEXPORT jlong JNICALL Java_kittoku_mvc_control_RustTunEngine_nativeCreate(
    JNIEnv *env, jobject receiver, jobject options, jlong now)
{
    (void)receiver;
    if (options == NULL || now < 0) return 0;
    const uint8_t *bytes = (*env)->GetDirectBufferAddress(env, options);
    jlong capacity = (*env)->GetDirectBufferCapacity(env, options);
    if (bytes == NULL || capacity < 0 || (uint64_t)capacity > SIZE_MAX) return 0;
    return (jlong)(intptr_t)softether_tun_create(bytes, (size_t)capacity, (uint64_t)now);
}

JNIEXPORT jint JNICALL Java_kittoku_mvc_control_RustTunEngine_nativeStep(
    JNIEnv *env, jobject receiver, jlong handle, jint frame_fd, jint tun_fd, jint mtu,
    jboolean reset, jlong now, jobject status)
{
    (void)receiver;
    if (status == NULL || now < 0) return -EINVAL;
    uint8_t *bytes = (*env)->GetDirectBufferAddress(env, status);
    jlong capacity = (*env)->GetDirectBufferCapacity(env, status);
    if (bytes == NULL || capacity < 0 || (uint64_t)capacity > SIZE_MAX) return -EINVAL;
    return softether_tun_step((TunSession *)(intptr_t)handle, frame_fd, tun_fd, mtu, reset,
        (uint64_t)now, bytes, (size_t)capacity);
}

JNIEXPORT void JNICALL Java_kittoku_mvc_control_RustTunEngine_nativeStop(
    JNIEnv *env, jobject receiver, jlong handle, jint frame_fd, jlong now)
{
    (void)env;
    (void)receiver;
    softether_tun_stop((TunSession *)(intptr_t)handle, frame_fd, now < 0 ? 0 : (uint64_t)now);
}
