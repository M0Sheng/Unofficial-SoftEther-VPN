package kittoku.mvc.network

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Handler
import androidx.annotation.StringRes
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.Closeable
import java.io.IOException

internal class PhysicalUnderlayLostException(
    val unavailableNetwork: Network? = null,
    @StringRes messageRes: Int = R.string.error_underlying_network_lost,
    cause: Throwable? = null,
) : IOException(appText(messageRes), cause)

internal data class PhysicalUnderlay(val network: Network, val transport: Int, val validated: Boolean)

internal fun ConnectivityManager.physicalUnderlay(network: Network): PhysicalUnderlay? {
    val caps = getNetworkCapabilities(network) ?: return null
    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
    val transport = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkCapabilities.TRANSPORT_WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkCapabilities.TRANSPORT_CELLULAR
        else -> return null
    }
    return PhysicalUnderlay(network, transport, caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
}

@Suppress("DEPRECATION")
internal fun ConnectivityManager.physicalUnderlays(excluded: Network? = null): List<PhysicalUnderlay> {
    val preferred = activeNetwork
    return (listOfNotNull(preferred) + allNetworks).distinct()
        .filterNot { it == excluded }
        .mapNotNull { physicalUnderlay(it) }
        .filter { candidate ->
            getLinkProperties(candidate.network)?.linkAddresses?.any { address ->
                !address.address.isAnyLocalAddress && !address.address.isLinkLocalAddress && !address.address.isLoopbackAddress
            } == true
        }
        .sortedWith(compareByDescending<PhysicalUnderlay> { it.network == preferred }
            .thenByDescending { it.validated }
            .thenByDescending { it.transport == NetworkCapabilities.TRANSPORT_WIFI })
}

/** Waits for a physical link during a handover, with callbacks delivered on the service handler. */
internal class PhysicalUnderlayWait(
    private val manager: ConnectivityManager,
    private val handler: Handler,
    private val excluded: Network?,
    private val complete: (available: Boolean) -> Unit,
) : Closeable {
    private var registered = false
    private var closed = false
    private val probe = Runnable { if (hasUsableLink()) finish(true) }
    private val expiry = Runnable { finish(hasUsableLink()) }
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = probeSoon()
        override fun onLost(network: Network) = probeSoon()
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = probeSoon()
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = probeSoon()
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .build()
        try {
            manager.registerNetworkCallback(request, callback, handler)
            registered = true
        } catch (_: RuntimeException) {
            finish(false)
            return
        }
        handler.postDelayed(expiry, WAIT_MILLIS)
        probeSoon()
    }

    private fun probeSoon() {
        if (closed) return
        // Check after Android publishes the new capabilities, address and default network together.
        handler.removeCallbacks(probe)
        handler.postDelayed(probe, SETTLE_MILLIS)
    }

    private fun hasUsableLink(): Boolean = manager.physicalUnderlays(excluded).isNotEmpty()

    private fun finish(available: Boolean) {
        if (closed) return
        close()
        complete(available)
    }

    override fun close() {
        if (closed) return
        closed = true
        handler.removeCallbacks(probe)
        handler.removeCallbacks(expiry)
        if (registered) runCatching { manager.unregisterNetworkCallback(callback) }
    }

    private companion object {
        const val WAIT_MILLIS = 30_000L
        const val SETTLE_MILLIS = 350L
    }
}
