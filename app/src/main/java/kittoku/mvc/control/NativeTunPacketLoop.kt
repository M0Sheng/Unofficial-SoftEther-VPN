package kittoku.mvc.control

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import io.github.m0sheng.unofficialsoftethervpn.link.FrameEndpoint
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.routing.TunDestinationFamilyRoutes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.IOException

/** Keeps Android TUN descriptors in sync with the Rust Ethernet and IP forwarding session. */
internal class NativeTunPacketLoop(
    private val endpoint: FrameEndpoint,
    private val mac: ByteArray,
    private val mtu: Int,
    private val ipv6Enabled: Boolean,
    private val ipv6Routes: TunDestinationFamilyRoutes?,
    private val lanOnly: Boolean,
    private val callbacks: Callbacks,
) {
    interface Callbacks {
        fun establish(
            lease: NativeTunIpv4Lease,
            ipv6: NativeTunIpv6Configuration?,
            mtu: Int,
        ): ParcelFileDescriptor

        fun onLeaseLost()
        fun onIpv6Unavailable(messageRes: Int)
        fun onIpv6Refresh()
        fun onTraffic(receivedBytes: Int, sentBytes: Int)
        fun logIpv6(level: String, message: String)
    }

    suspend fun run(): Unit = withContext(Dispatchers.IO) {
        endpoint.use { frameEndpoint ->
            frameEndpoint.duplicateForForwarding().use { descriptor ->
                var tunnel: ParcelFileDescriptor? = null
                var tunnelMtu = mtu
                var installedLease: NativeTunIpv4Lease? = null
                var installedIpv6: NativeTunIpv6Configuration? = null
                var reportedIpv6 = NativeTunIpv6Status.DISABLED
                var resetQueues = false
                try {
                    RustTunEngine(descriptor.fd, mac, mtu, ipv6Enabled, ipv6Routes, lanOnly).use { engine ->
                        while (true) {
                            ensureActive()
                            val changed = engine.step(tunnel?.fd ?: -1, tunnelMtu, resetQueues)
                            resetQueues = false
                            ensureActive()
                            if (engine.receivedBytes != 0 || engine.sentBytes != 0) {
                                callbacks.onTraffic(engine.receivedBytes, engine.sentBytes)
                            }
                            if (!changed) continue
                            val state = engine.addresses()
                            if (state.leaseLost) {
                                val previous = tunnel
                                tunnel = null
                                previous?.close()
                                callbacks.onLeaseLost()
                                throw IOException(appText(R.string.network_runtime_error_dhcp_lease_expired))
                            }
                            if (state.ipv6Status == NativeTunIpv6Status.EXPIRED) {
                                callbacks.onIpv6Refresh()
                                throw IOException(appText(R.string.network_runtime_error_slaac_lease_expired))
                            }
                            val lease = state.lease ?: continue
                            if (state.ipv6Status == NativeTunIpv6Status.DISCOVERING) continue
                            if (state.ipv6Status != reportedIpv6) {
                                reportIpv6(state)
                                reportedIpv6 = state.ipv6Status
                            }
                            if (tunnel != null && installedLease == lease && installedIpv6 == state.ipv6) continue

                            val selectedMtu = minOf(mtu, state.ipv6?.mtu ?: mtu)
                            val replacement = callbacks.establish(lease, state.ipv6, selectedMtu)
                            setNonblocking(replacement)
                            val previous = tunnel
                            tunnel = replacement
                            tunnelMtu = selectedMtu
                            installedLease = lease
                            installedIpv6 = state.ipv6
                            resetQueues = previous != null
                            previous?.close()
                        }
                    }
                } finally {
                    runCatching { tunnel?.close() }
                }
            }
        }
    }

    private fun setNonblocking(descriptor: ParcelFileDescriptor) {
        try {
            val fd = descriptor.fileDescriptor
            val flags = Os.fcntlInt(fd, OsConstants.F_GETFL, 0)
            Os.fcntlInt(fd, OsConstants.F_SETFL, flags or OsConstants.O_NONBLOCK)
        } catch (error: ErrnoException) {
            runCatching { descriptor.close() }
            throw error.rethrowAsIOException()
        }
    }

    private fun reportIpv6(state: NativeTunAddresses) {
        when (state.ipv6Status) {
            NativeTunIpv6Status.READY -> {
                val configuration = requireNotNull(state.ipv6)
                callbacks.logIpv6("INFO", "SLAAC address acquired; default_router_required=" +
                    configuration.usesDefaultRouter + "; mtu=" + configuration.mtu)
            }
            NativeTunIpv6Status.MTU_TOO_SMALL -> callbacks.onIpv6Unavailable(R.string.tun_ipv6_mtu_too_small)
            NativeTunIpv6Status.DUPLICATE -> callbacks.onIpv6Unavailable(R.string.tun_ipv6_duplicate_address)
            NativeTunIpv6Status.NO_ADVERTISEMENT -> callbacks.onIpv6Unavailable(R.string.tun_ipv6_no_advertisement)
            else -> Unit
        }
    }
}
