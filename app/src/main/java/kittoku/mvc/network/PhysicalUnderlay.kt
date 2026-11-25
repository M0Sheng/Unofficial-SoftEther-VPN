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

private fun LinkProperties.hasUsableAddress(): Boolean = linkAddresses.any { address ->
    !address.address.isAnyLocalAddress && !address.address.isLinkLocalAddress && !address.address.isLoopbackAddress
}

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
internal fun ConnectivityManager.physicalUnderlays(): List<PhysicalUnderlay> {
    val preferred = activeNetwork
    return (listOfNotNull(preferred) + allNetworks).distinct()
        .mapNotNull { physicalUnderlay(it) }
        .filter { getLinkProperties(it.network)?.hasUsableAddress() == true }
        .sortedWith(compareByDescending<PhysicalUnderlay> { it.network == preferred }
            .thenByDescending { it.validated }
            .thenByDescending { it.transport == NetworkCapabilities.TRANSPORT_WIFI })
}

internal class PhysicalLinkSelection<T : Any> {
    private var offered: T? = null
    var ready: T? = null
        private set

    fun offer(network: T): Boolean {
        if (offered == network) return false
        offered = network
        ready = null
        return true
    }

    fun addressChanged(network: T, usable: Boolean): Boolean {
        if (network != offered) return false
        val candidate = network.takeIf { usable }
        if (ready == candidate) return false
        ready = candidate
        return true
    }

    fun lost(network: T): Boolean {
        if (network != offered) return false
        offered = null
        ready = null
        return true
    }
}

/** Android selects the preferred physical link independently of the app's VPN default network. */
internal class PhysicalUnderlayMonitor(
    private val manager: ConnectivityManager,
    private val handler: Handler,
    private val onChanged: (Network?) -> Unit,
) : Closeable {
    private var registered = false
    private var closed = false
    private val selection = PhysicalLinkSelection<Network>()
    val readyNetwork: Network? get() = selection.ready
    private val dispatch = Runnable { if (!closed) onChanged(readyNetwork) }

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (selection.offer(network)) dispatchAfterSettling()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (selection.addressChanged(network, linkProperties.hasUsableAddress())) dispatchAfterSettling()
        }

        override fun onLost(network: Network) {
            if (selection.lost(network)) dispatchAfterSettling()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .build()
        manager.registerBestMatchingNetworkCallback(request, callback, handler)
        registered = true
    }

    fun dispatchAfterSettling() {
        if (closed) return
        handler.removeCallbacks(dispatch)
        handler.postDelayed(dispatch, SETTLE_MILLIS)
    }

    override fun close() {
        if (closed) return
        closed = true
        handler.removeCallbacks(dispatch)
        if (registered) runCatching { manager.unregisterNetworkCallback(callback) }
    }

    companion object {
        const val SETTLE_MILLIS = 350L
    }
}
