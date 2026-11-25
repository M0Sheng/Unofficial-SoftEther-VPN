package kittoku.mvc.control

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kittoku.mvc.R
import kittoku.mvc.nativecore.NativeCertificateVerification
import kittoku.mvc.nativecore.NativeConnectionSecurity
import java.io.Closeable
import java.net.Inet4Address
import java.net.Inet6Address
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

internal class NetworkStatusMonitor(
    private val connection: ConnectionContext,
    private val tap: Boolean,
    private val owns: (LinkProperties) -> Boolean,
    private val statusDetails: () -> List<String> = { emptyList() },
    private val connectionSecurity: () -> NativeConnectionSecurity? = { null },
) : Closeable {
    private val manager = connection.service.getSystemService(ConnectivityManager::class.java)
    private val transport = if (tap) NetworkCapabilities.TRANSPORT_ETHERNET else NetworkCapabilities.TRANSPORT_VPN
    private val closed = AtomicBoolean(false)
    private val registration = ArrayList<ConnectivityManager.NetworkCallback>(3)
    private var lastMessage = ""
    @Volatile var interfaceName: String? = null
        private set
    @Volatile var hasUsableAddress = false
        private set

    private val interfaceCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (owns(properties)) describe(network, properties) else refresh()
        }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = refresh()
        override fun onLost(network: Network) = refresh()
    }
    private val underlayCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (connection.underlyingNetwork == network) refresh()
        }
        override fun onLost(network: Network) {
            if (!closed.get() && connection.underlyingNetwork == network) {
                connection.service.onUnderlyingNetworkLost(connection, network)
            }
        }
    }
    private val appDefaultCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = refreshAfterDefaultChange()
        override fun onLost(network: Network) = refreshAfterDefaultChange()
    }

    init {
        try {
            val request = NetworkRequest.Builder().addTransportType(transport)
            if (!tap) request.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            manager.registerNetworkCallback(request.build(), interfaceCallback)
            registration.add(interfaceCallback)
            if (tap) {
                val internet = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
                manager.registerNetworkCallback(internet, underlayCallback)
                registration.add(underlayCallback)
                manager.registerDefaultNetworkCallback(appDefaultCallback)
                registration.add(appDefaultCallback)
            }
            refresh()
        } catch (failure: RuntimeException) {
            close()
            throw failure
        }
    }

    private fun refreshAfterDefaultChange() {
        // Read the app's default after ConnectivityManager has dispatched its event.
        connection.service.mainExecutor.execute { refresh() }
    }

    @Suppress("DEPRECATION")
    @Synchronized fun refresh() {
        if (closed.get()) return
        val link = manager.allNetworks.firstNotNullOfOrNull { network ->
            if (manager.getNetworkCapabilities(network)?.hasTransport(transport) != true) null
            else manager.getLinkProperties(network)?.takeIf(owns)?.let { network to it }
        }
        if (link != null) {
            describe(link.first, link.second)
        } else {
            interfaceName = null
            hasUsableAddress = false
            if (tap) {
                val status = connection.service.getString(R.string.vpn_virtual_adapter_waiting)
                publish((listOf(status) + securityDetails()).joinToString("\n"))
            }
        }
    }

    @Synchronized private fun describe(network: Network, properties: LinkProperties) {
        if (closed.get() || !owns(properties)) return
        interfaceName = properties.interfaceName
        val service = connection.service
        hasUsableAddress = properties.linkAddresses.any {
            val ip = it.address
            !ip.isAnyLocalAddress && !ip.isLinkLocalAddress && !ip.isLoopbackAddress
        }
        val header = when {
            !tap -> R.string.status_connected
            hasUsableAddress -> R.string.vpn_virtual_adapter_connected
            else -> R.string.vpn_virtual_adapter_waiting
        }
        val body = buildList {
            add(service.getString(header))
            properties.interfaceName?.let { add(service.getString(R.string.vpn_virtual_adapter_interface, it)) }
            addAll(statusDetails())
            if (tap) {
                add("")
                add(service.getString(R.string.network_runtime_network_details_validation))
                add(validation(service.getString(R.string.network_runtime_network_details_underlay), connection.underlyingNetwork))
                add(validation(service.getString(R.string.network_runtime_network_details_virtual_adapter), network))
                add(validation(service.getString(R.string.network_runtime_network_details_app_default), manager.activeNetwork))
            }
            add("")
            add(service.getString(R.string.network_runtime_network_details_ipv4))
            addAll(properties.linkAddresses.filter { it.address is Inet4Address }.map { it.toString() }.ifEmpty { listOf(service.getString(R.string.network_runtime_network_details_address_unassigned)) })
            add("")
            add(service.getString(R.string.network_runtime_network_details_ipv6))
            addAll(properties.linkAddresses.filter { it.address is Inet6Address }.map { it.toString() }.ifEmpty { listOf(service.getString(R.string.network_runtime_network_details_address_unassigned)) })
            addAll(securityDetails())
            add("")
            add(service.getString(R.string.network_runtime_network_details_system_dns))
            addAll(properties.dnsServers.mapNotNull { it.hostAddress }.ifEmpty { listOf(service.getString(R.string.network_runtime_network_details_dns_unavailable)) })
            add("")
            add(service.getString(R.string.network_runtime_network_details_system_routes))
            addAll(properties.routes.map { it.toString() }.ifEmpty { listOf(service.getString(R.string.network_runtime_network_details_no_routes)) })
        }
        publish(body.joinToString("\n"))
    }

    private fun securityDetails(): List<String> {
        val security = connectionSecurity() ?: return emptyList()
        val service = connection.service
        val unknown = service.getString(R.string.network_security_unknown)
        return buildList {
            add("")
            add(service.getString(R.string.network_security_heading))
            add(service.getString(R.string.network_security_tls_version, security.tlsVersion ?: unknown))
            add(service.getString(R.string.network_security_cipher, security.cipherSuite ?: unknown))
            val encryption = when (security.encryptionEnabled) {
                true -> R.string.network_security_encryption_on
                false -> R.string.network_security_encryption_off
                null -> R.string.network_security_unknown
            }
            add(service.getString(R.string.network_security_encryption, service.getString(encryption)))
            val verification = when (security.verification) {
                NativeCertificateVerification.SYSTEM_CA -> R.string.network_security_system_ca
                NativeCertificateVerification.SAVED_PIN -> R.string.network_security_saved_pin
                NativeCertificateVerification.NATIVE_VERIFIED -> R.string.network_security_native_verified
                NativeCertificateVerification.UNVERIFIED -> R.string.network_security_unverified
                NativeCertificateVerification.UNKNOWN -> R.string.network_security_unknown
            }
            val certificate = security.serverCertificate
            add(service.getString(R.string.network_security_subject, certificate?.subject?.ifBlank { unknown } ?: unknown))
            if (certificate != null) {
                add(service.getString(R.string.network_security_issuer, certificate.issuer.ifBlank { unknown }))
                add(service.getString(R.string.network_security_expiry, CERTIFICATE_DATE.format(Instant.ofEpochMilli(certificate.expiresAtMillis))))
                add(service.getString(R.string.network_security_fingerprint_sha256, formatFingerprint(certificate.sha256)))
                add(service.getString(R.string.network_security_fingerprint_sha1, formatFingerprint(certificate.sha1)))
            }
            add(service.getString(R.string.network_security_verification, service.getString(verification)))
        }
    }

    private fun formatFingerprint(hex: String): String =
        hex.replace(":", "").uppercase(Locale.ROOT).chunked(2).joinToString(":")

    private fun validation(label: String, network: Network?): String {
        val capabilities = network?.let(manager::getNetworkCapabilities)
        val verdict = when {
            capabilities == null -> connection.service.getString(R.string.network_runtime_network_validation_unknown)
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) -> connection.service.getString(R.string.network_runtime_network_validation_validated)
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) -> connection.service.getString(R.string.network_runtime_network_validation_sign_in)
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) -> connection.service.getString(R.string.network_runtime_network_validation_local)
            else -> connection.service.getString(R.string.network_runtime_network_validation_failed)
        }
        val device = network?.let(manager::getLinkProperties)?.interfaceName
        return listOfNotNull(label, device, verdict).joinToString(" · ")
    }

    private fun publish(message: String) {
        if (!closed.get() && lastMessage != message) {
            lastMessage = message
            DiagnosticLog.record("INFO", "NETWORK", message, connection.sessionId)
            connection.service.updateConnectionStatus(connection, message) { !closed.get() }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        registration.forEach { callback -> runCatching { manager.unregisterNetworkCallback(callback) } }
        interfaceName = null
        hasUsableAddress = false
    }

    private companion object {
        val CERTIFICATE_DATE: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'", Locale.ROOT)
            .withZone(ZoneOffset.UTC)
    }
}
