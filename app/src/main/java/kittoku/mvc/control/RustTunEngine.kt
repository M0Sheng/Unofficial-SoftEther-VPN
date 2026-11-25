package kittoku.mvc.control

import android.os.SystemClock
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.routing.TunDestinationFamilyRoutes
import java.io.Closeable
import java.io.IOException
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

internal data class NativeTunIpv4Route(val destination: Int, val prefixLength: Int, val gateway: Int)

internal data class NativeTunIpv4Lease(
    val address: Int,
    val prefixLength: Int,
    val dns: List<Int>,
    val routes: List<NativeTunIpv4Route>,
)

internal data class NativeTunIpv6Configuration(
    val address: Inet6Address,
    val onLinkPrefix: Inet6Address?,
    val mtu: Int,
    val usesDefaultRouter: Boolean,
)

internal enum class NativeTunIpv6Status { DISABLED, DISCOVERING, READY, MTU_TOO_SMALL, DUPLICATE, NO_ADVERTISEMENT, EXPIRED }

internal data class NativeTunAddresses(
    val lease: NativeTunIpv4Lease?,
    val leaseLost: Boolean,
    val ipv6Status: NativeTunIpv6Status,
    val ipv6: NativeTunIpv6Configuration?,
)

/** The packet worker exclusively owns the native engine and borrows the descriptors during each call. */
internal class RustTunEngine(
    private val frameFd: Int,
    mac: ByteArray,
    mtu: Int,
    ipv6Enabled: Boolean,
    ipv6Routes: TunDestinationFamilyRoutes?,
    lanOnly: Boolean,
) : Closeable {
    private val status = ByteBuffer.allocateDirect(SNAPSHOT_SIZE).order(ByteOrder.nativeOrder())
    private var handle: Long

    var receivedBytes: Int = 0
        private set
    var sentBytes: Int = 0
        private set

    init {
        require(mac.size == 6)
        val included = ipv6Routes?.included.orEmpty()
        val excluded = ipv6Routes?.excluded.orEmpty()
        val options = ByteBuffer.allocateDirect(34 + (included.size + excluded.size) * 17)
            .order(ByteOrder.nativeOrder())
        val random = SecureRandom()
        val identifier = ByteArray(8)
        if (ipv6Enabled) random.nextBytes(identifier)
        val routerPolicy = when {
            ipv6Routes != null -> 2
            lanOnly -> 1
            else -> 0
        }
        val flags = (if (ipv6Enabled) 1 else 0) or (if (lanOnly) 0 else 2) or (routerPolicy shl 2)
        options.put(mac).put(identifier).putInt(mtu).putInt(flags)
            .putInt(if (ipv6Enabled) random.nextInt(1_000) else 0)
            .putInt(included.size).putInt(excluded.size)
        for (prefix in included + excluded) {
            options.put(prefix.addressBytes()).put(prefix.prefixLength.toByte())
        }
        handle = nativeCreate(options, SystemClock.elapsedRealtime())
        if (handle == 0L) throw IOException(appText(R.string.network_runtime_error_tun_engine_init))
    }

    fun step(tunFd: Int, mtu: Int, resetQueues: Boolean): Boolean {
        check(handle != 0L)
        val result = nativeStep(handle, frameFd, tunFd, mtu, resetQueues, SystemClock.elapsedRealtime(), status)
        if (result != 0) throw IOException(appText(R.string.network_runtime_error_tun_engine_forward, -result))
        status.rewind()
        receivedBytes = status.int
        sentBytes = status.int
        return status.int != 0
    }

    fun addresses(): NativeTunAddresses = decodeTunAddresses(status)

    override fun close() {
        val current = handle
        if (current == 0L) return
        handle = 0L
        nativeStop(current, frameFd, SystemClock.elapsedRealtime())
    }

    private external fun nativeCreate(options: ByteBuffer, now: Long): Long
    private external fun nativeStep(
        handle: Long, frameFd: Int, tunFd: Int, mtu: Int, resetQueues: Boolean, now: Long, status: ByteBuffer,
    ): Int
    private external fun nativeStop(handle: Long, frameFd: Int, now: Long)

    private companion object {
        const val SNAPSHOT_SIZE = 16_384
        init {
            System.loadLibrary("homevpn_tun")
        }
    }
}

internal fun decodeTunAddresses(status: ByteBuffer): NativeTunAddresses {
    val flags = status.int
    val ipv6Status = NativeTunIpv6Status.entries[status.int]
    val lease = if (flags and 1 != 0) {
        val address = status.int
        val prefix = status.int
        val dnsCount = status.int
        val routeCount = status.int
        val dns = List(dnsCount) { status.int }
        val routes = List(routeCount) { NativeTunIpv4Route(status.int, status.int, status.int) }
        NativeTunIpv4Lease(address, prefix, dns, routes)
    } else null
    val ipv6 = if (ipv6Status == NativeTunIpv6Status.READY) {
        val address = status.readIpv6()
        val mtu = status.int
        val ipv6Flags = status.int
        val prefix = if (ipv6Flags and 1 != 0) status.readIpv6() else null
        NativeTunIpv6Configuration(address, prefix, mtu, ipv6Flags and 2 != 0)
    } else null
    return NativeTunAddresses(lease, flags and 2 != 0, ipv6Status, ipv6)
}

private fun ByteBuffer.readIpv6(): Inet6Address =
    Inet6Address.getByAddress(null, ByteArray(16).also { get(it) }, -1)
