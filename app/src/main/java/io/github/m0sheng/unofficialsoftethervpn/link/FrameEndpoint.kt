package io.github.m0sheng.unofficialsoftethervpn.link

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.Closeable
import java.io.EOFException
import java.io.FileDescriptor
import java.io.IOException
import java.util.UUID
import java.util.concurrent.TimeUnit

/** App-side Ethernet link to a directly launched SoftEther child. */
class FrameEndpoint private constructor(private val descriptor: FileDescriptor) : Closeable {
    private var closed = false

    /** Return a nonblocking duplicate that the forwarding worker owns and closes. */
    @Synchronized
    @Throws(IOException::class)
    fun duplicateForForwarding(): ParcelFileDescriptor {
        if (closed) throw IOException("Ethernet frame endpoint is closed")
        return ParcelFileDescriptor.dup(descriptor)
    }

    @Synchronized
    @Throws(IOException::class)
    override fun close() {
        if (closed) return
        closed = true
        try {
            Os.close(descriptor)
        } catch (error: ErrnoException) {
            throw error.rethrowAsIOException()
        }
    }

    class Listener internal constructor(private val name: String) : Closeable {
        private val server = LocalServerSocket(name)
        private var consumed = false

        fun name(): String = name

        /**
         * Accept the child once. Its private output pipe must start with the line
         * FRAME_CHILD_PID=<pid>. The caller owns the Process and can begin draining
         * its remaining output after this returns.
         */
        @Synchronized
        @Throws(IOException::class, InterruptedException::class)
        fun accept(child: Process): FrameEndpoint {
            if (consumed) throw IOException("Ethernet frame listener is already closed")
            consumed = true
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(HANDOFF_MILLIS)
            val app = FileDescriptor()
            val nativePeer = FileDescriptor()
            var keepApp = false
            try {
                server.use { listener ->
                    val pid = readChildPid(child, deadline)
                    nonblocking(listener.fileDescriptor)
                    awaitControl(listener, child, pid, deadline).use { socket ->
                        Os.socketpair(
                            OsConstants.AF_UNIX,
                            OsConstants.SOCK_SEQPACKET or OsConstants.SOCK_CLOEXEC,
                            0, app, nativePeer,
                        )
                        nonblocking(app)
                        nonblocking(socket.fileDescriptor)
                        socket.setFileDescriptorsForSend(arrayOf(nativePeer))
                        socket.outputStream.write('F'.code)
                        Os.close(nativePeer)
                    }
                }
                val endpoint = FrameEndpoint(app)
                keepApp = true
                return endpoint
            } catch (error: ErrnoException) {
                throw error.rethrowAsIOException()
            } finally {
                closeQuietly(nativePeer)
                if (!keepApp) closeQuietly(app)
            }
        }

        @Synchronized
        @Throws(IOException::class)
        override fun close() {
            if (consumed) return
            consumed = true
            server.close()
        }
    }

    companion object {
        const val SOCKET_ENVIRONMENT = "HOMEVPN_FRAME_SOCKET"

        private const val HANDOFF_MILLIS = 4_000L
        private const val MAX_POLL_MILLIS = 250L
        private const val PID_PREFIX = "FRAME_CHILD_PID="

        /** Open the private rendezvous before starting the native process. */
        @JvmStatic
        @Throws(IOException::class)
        fun listen(): Listener = Listener("softether-frame-" + UUID.randomUUID())

        private fun readChildPid(child: Process, deadline: Long): Int {
            val output = child.inputStream
            val line = ByteArray(32)
            var size = 0
            while (remainingMillis(deadline) > 0) {
                if (Thread.interrupted()) throw InterruptedException()
                if (output.available() == 0) {
                    if (!child.isAlive) throw EOFException("SoftEther exited before PID announcement")
                    Thread.sleep(10)
                    continue
                }
                val next = output.read()
                if (next < 0) throw EOFException("SoftEther output ended before PID announcement")
                if (next == '\n'.code) return parsePid(line, size)
                if (size == line.size) throw IOException("SoftEther PID announcement is too long")
                line[size++] = next.toByte()
            }
            throw IOException("Timed out waiting for the SoftEther PID announcement")
        }

        private fun parsePid(bytes: ByteArray, size: Int): Int {
            val length = if (size > 0 && bytes[size - 1] == '\r'.code.toByte()) size - 1 else size
            val line = String(bytes, 0, length, Charsets.US_ASCII)
            if (line.startsWith(PID_PREFIX) && line.length > PID_PREFIX.length) {
                val number = line.substring(PID_PREFIX.length)
                if (number[0] != '0' && number.all { it in '0'..'9' }) {
                    val pid = number.toIntOrNull()
                    if (pid != null && pid > 1) return pid
                }
            }
            throw IOException("Invalid SoftEther PID announcement")
        }

        private fun awaitControl(listener: LocalServerSocket, child: Process, pid: Int, deadline: Long): LocalSocket {
            val pending = StructPollfd().apply { fd = listener.fileDescriptor }
            val entries = arrayOf(pending)
            while (true) {
                val wait = remainingMillis(deadline)
                if (wait <= 0) break
                if (Thread.interrupted()) throw InterruptedException()
                if (!child.isAlive) throw EOFException("SoftEther exited before frame handoff")
                if (poll(pending, entries, wait) and OsConstants.POLLIN == 0) continue

                val socket = listener.accept()
                var authenticated = false
                try {
                    val peer = socket.peerCredentials
                    authenticated = peer.uid == android.os.Process.myUid() && peer.pid == pid && child.isAlive
                    if (authenticated) return socket
                } finally {
                    if (!authenticated) socket.close()
                }
            }
            throw IOException("Timed out waiting for the authenticated Ethernet frame endpoint")
        }

        private fun poll(entry: StructPollfd, entries: Array<StructPollfd>, timeout: Int): Int {
            entry.events = OsConstants.POLLIN.toShort()
            entry.revents = 0
            try {
                Os.poll(entries, timeout)
            } catch (error: ErrnoException) {
                if (error.errno == OsConstants.EINTR) return 0
                throw error
            }
            val ready = entry.revents.toInt()
            if (ready and (OsConstants.POLLERR or OsConstants.POLLNVAL) != 0) {
                throw IOException("Packet endpoint poll failed")
            }
            return ready
        }

        private fun remainingMillis(deadline: Long): Int {
            val nanos = deadline - System.nanoTime()
            if (nanos <= 0) return 0
            return TimeUnit.NANOSECONDS.toMillis(nanos).coerceIn(1, MAX_POLL_MILLIS).toInt()
        }

        private fun nonblocking(descriptor: FileDescriptor) {
            val flags = Os.fcntlInt(descriptor, OsConstants.F_GETFL, 0)
            Os.fcntlInt(descriptor, OsConstants.F_SETFL, flags or OsConstants.O_NONBLOCK)
        }

        private fun closeQuietly(descriptor: FileDescriptor) {
            if (descriptor.valid()) {
                try {
                    Os.close(descriptor)
                } catch (_: ErrnoException) {
                    // Keep the setup failure available to the caller.
                }
            }
        }
    }
}
