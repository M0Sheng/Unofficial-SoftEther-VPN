package kittoku.mvc.control

import android.net.IpPrefix
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import io.github.m0sheng.unofficialsoftethervpn.link.FrameEndpoint
import kittoku.mvc.R
import kittoku.mvc.nativecore.TunNativeSession
import kittoku.mvc.network.IPv4Cidr
import kittoku.mvc.network.ipv4Bytes
import kittoku.mvc.network.isUnicastIPv4
import kittoku.mvc.routing.AppRoutingSettings
import kittoku.mvc.routing.RootBypassCidr
import kittoku.mvc.routing.RoutingBypassSettings
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationRoutes
import kittoku.mvc.routing.resolveTunDestinationRoutes
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

internal class TunConnection(private val connection: ConnectionContext) {
    private val service = connection.service
    private val sessionId = connection.sessionId
    private val interfaceLock = Any()
    private val closing = AtomicBoolean()
    @Volatile private var activeAddresses = emptySet<InetAddress>()
    @Volatile private var monitor: NetworkStatusMonitor? = null
    @Volatile private var routingSummary = emptyList<Int>()

    val interfaceName: String? get() = monitor?.interfaceName

    private val transport = TunNativeSession(service, TunNativeSession.Config(
        serverHostname = connection.serverHostname,
        serverPort = connection.serverPort,
        hub = connection.serverHubName,
        username = connection.clientUsername,
        authentication = connection.authentication,
        certificateSha256 = connection.certificateSha256,
        sslVersion = connection.sslVersion,
        cipherSuites = connection.cipherSuites,
        enableUdpAcceleration = connection.useUdpAcceleration,
        ipv6Enabled = connection.tunIpv6Forward,
        requestedMac = connection.tunMac,
        sessionId = sessionId,
        excludedUnderlay = connection.excludedUnderlay,
    ), object : TunNativeSession.Callbacks {
        override fun onReady(network: Network, endpoint: FrameEndpoint, mac: ByteArray) {
            connection.underlyingNetwork = network
            connection.scope.launch(connection.handler) {
                if (!closing.get()) runTunnel(network, endpoint, mac)
            }
        }
        override fun onStatus(message: String) = service.updateConnectionStatus(connection, message)
        override fun onSecurityChanged() { if (!closing.get()) monitor?.refresh() }
        override fun onStopped(error: Throwable) = kill(error)
    })

    fun refreshStatus(): Boolean {
        val observer = monitor ?: return false
        observer.refresh()
        return observer.interfaceName != null
    }

    fun run() {
        transport.start()
    }

    private suspend fun runTunnel(network: Network, endpoint: FrameEndpoint, mac: ByteArray) {
        val modern = connection.destinationConfiguration?.let {
            resolveTunDestinationRoutes(it, network, connection.tunIpv6Forward, sessionId)
        }
        val legacyExclusions = if (modern == null) RoutingBypassSettings(service).resolveForTun(network, sessionId)
            else emptyList()
        val attempt = connection.scope.launch {
            delay(45_000)
            if (activeAddresses.isEmpty()) kill(IOException(service.getString(R.string.network_runtime_error_vpn_address_deadline)))
        }
        service.updateConnectionStatus(connection, service.getString(R.string.status_getting_address))
        val ipv6Requested = connection.tunIpv6Forward && modern?.ipv6?.hasRoutes != false
        val packets = NativeTunPacketLoop(
            endpoint, mac, connection.tunMtu, ipv6Requested,
            ipv6Routes = modern?.ipv6,
            lanOnly = connection.legacyLanOnly,
            callbacks = object : NativeTunPacketLoop.Callbacks {
                override fun establish(
                    lease: NativeTunIpv4Lease, ipv6: NativeTunIpv6Configuration?, mtu: Int,
                ): ParcelFileDescriptor {
                    val fd = synchronized(interfaceLock) {
                        if (closing.get()) throw IOException(service.getString(R.string.network_runtime_error_connection_closed))
                        installTun(network, lease, ipv6, modern, legacyExclusions, mtu)
                    }
                    attempt.cancel()
                    service.onSessionConnected(this@TunConnection, ipv6Requested && ipv6 == null)
                    return fd
                }
                override fun onLeaseLost() {
                    activeAddresses = emptySet()
                    kill(IOException(service.getString(R.string.network_runtime_error_dhcp_lease_expired)))
                }
                override fun onIpv6Unavailable(messageRes: Int) {
                    DiagnosticLog.record("WARN", "TUN_IPV6", service.getString(messageRes), sessionId)
                }
                override fun onIpv6Refresh() = kill(IOException(service.getString(R.string.network_runtime_error_ipv6_address_renew)))
                override fun onTraffic(receivedBytes: Int, sentBytes: Int) {
                    TrafficMeter.received(sessionId, receivedBytes.toLong())
                    TrafficMeter.sent(sessionId, sentBytes.toLong())
                }
                override fun logIpv6(level: String, message: String) {
                    DiagnosticLog.record(level, "TUN_IPV6", message, sessionId)
                }
            },
        )
        try {
            packets.run()
            if (!closing.get()) kill(IOException(service.getString(R.string.network_runtime_error_native_ethernet_closed)))
        } finally {
            attempt.cancel()
        }
    }

    private fun installTun(
        network: Network, lease: NativeTunIpv4Lease, ipv6: NativeTunIpv6Configuration?,
        modern: TunDestinationRoutes?, legacyExclusions: List<IPv4Cidr>, mtu: Int,
    ): ParcelFileDescriptor {
        val mode = connection.destinationConfiguration?.mode
        val routeV4 = modern?.ipv4?.hasRoutes != false
        val routeV6 = ipv6 != null && modern?.ipv6?.hasRoutes != false &&
            (!connection.legacyLanOnly || ipv6.onLinkPrefix != null)
        require(routeV4 || routeV6) { service.getString(R.string.network_runtime_error_vpn_routes_unavailable) }
        val ipv4 = unsigned(lease.address)
        val localSubnet = IPv4Cidr.of(ipv4, lease.prefixLength)
        val ipBytes = ipv4Bytes(ipv4)
        val useDefault = mode == TunDestinationMode.ALL || mode == TunDestinationMode.EXCLUDE ||
            (modern == null && !connection.legacyLanOnly)
        if (routeV4 && useDefault && (modern?.ipv4?.hasRoutesOutside(RootBypassCidr.parse(localSubnet.toString())) != false)) {
            requireUsableDefault(lease, localSubnet)
        }
        val addresses = linkedSetOf<InetAddress>()
        val builder = service.Builder()
            .setSession(service.getString(R.string.vpn_route_session_name, service.getString(connection.tunRoutingLabel)))
            .setBlocking(false)
            .setUnderlyingNetworks(arrayOf(network))
            .setMtu(mtu)
        if (routeV4) {
            val address = InetAddress.getByAddress(ipBytes)
            builder.addAddress(address, 32)
            addresses.add(address)
            val legacyRoutes = if (connection.legacyLanOnly) listOf(localSubnet) + connection.legacyLanRoutes
                else listOf(IPv4Cidr.of(0, 0))
            if (modern == null) {
                legacyRoutes.distinct().forEach { builder.addRoute(InetAddress.getByAddress(ipv4Bytes(it.network)), it.prefix) }
                legacyExclusions.forEach { builder.excludeRoute(IpPrefix(InetAddress.getByAddress(ipv4Bytes(it.network)), it.prefix)) }
            } else {
                modern.ipv4.included.forEach { builder.addRoute(IpPrefix(it.toInetAddress(), it.prefixLength)) }
                modern.ipv4.excluded.forEach { builder.excludeRoute(IpPrefix(it.toInetAddress(), it.prefixLength)) }
            }
            fun captures(bytes: ByteArray): Boolean = modern?.ipv4?.captures(bytes) ?: run {
                val candidate = kittoku.mvc.network.ipv4Address(bytes)
                legacyRoutes.any { it.contains(candidate) } && legacyExclusions.none { it.contains(candidate) }
            }
            val dns = lease.dns.map(::unsigned).filter { it != ipv4 && isUnicastIPv4(it) && !localSubnet.isBroadcast(it) }
                .map(::ipv4Bytes).filter(::captures)
            val dnsServers = if (useDefault && dns.isEmpty()) {
                listOf(byteArrayOf(1, 1, 1, 1), byteArrayOf(8, 8, 8, 8)).filter(::captures)
            } else dns
            require(!useDefault || dnsServers.isNotEmpty()) { service.getString(R.string.network_runtime_error_vpn_dns_excluded) }
            dnsServers.forEach { builder.addDnsServer(InetAddress.getByAddress(it)) }
        } else builder.allowFamily(OsConstants.AF_INET)

        if (ipv6 != null && routeV6) {
            builder.addAddress(ipv6.address, 128)
            addresses.add(ipv6.address)
            if (modern != null) {
                modern.ipv6.included.forEach { builder.addRoute(IpPrefix(it.toInetAddress(), it.prefixLength)) }
                modern.ipv6.excluded.forEach { builder.excludeRoute(IpPrefix(it.toInetAddress(), it.prefixLength)) }
            } else if (connection.legacyLanOnly) {
                builder.addRoute(requireNotNull(ipv6.onLinkPrefix), 64)
            } else builder.addRoute("::", 0)
        } else if (connection.tunIpv6Forward && modern?.ipv6?.hasRoutes == false ||
            !connection.tunIpv6Forward && connection.tunAllowsOriginalIpv6WhenOff) {
            builder.allowFamily(OsConstants.AF_INET6)
        }

        AppRoutingSettings(service).applyTo(builder, sessionId)
        val fd = builder.establish() ?: throw IOException(service.getString(R.string.network_runtime_error_android_vpn_interface_permission))
        try {
            activeAddresses = addresses
            routingSummary = listOf(
                connection.tunRoutingLabel,
                when {
                    routeV6 -> R.string.tun_ipv6_active
                    connection.tunIpv6Forward && modern?.ipv6?.hasRoutes == false -> R.string.tun_ipv6_no_targets
                    connection.tunIpv6Forward -> R.string.tun_ipv6_ipv4_only
                    connection.tunAllowsOriginalIpv6WhenOff -> R.string.tun_ipv6_disabled_lan
                    else -> R.string.tun_ipv6_disabled_full
                },
                R.string.network_runtime_network_details_transport,
                if (connection.useUdpAcceleration) R.string.network_runtime_network_transport_udp_allowed
                else R.string.network_runtime_network_transport_tcp_tls,
            )
            val observer = monitor
            if (observer == null) {
                monitor = NetworkStatusMonitor(
                    connection,
                    tap = false,
                    owns = { properties -> properties.linkAddresses.any { it.address in activeAddresses } },
                    statusDetails = { routingSummary.map { service.getString(it) } },
                    connectionSecurity = { transport.connectionSecurity },
                )
            } else observer.refresh()
            return fd
        } catch (failure: Throwable) {
            activeAddresses = emptySet()
            runCatching { fd.close() }
            throw failure
        }
    }

    fun kill(error: Throwable?) {
        if (!closing.compareAndSet(false, true)) return
        // An already-rejected native account can close Ethernet before its stop callback runs.
        val failure = error?.let { transport.connectionFailure() ?: it }
        if (failure != null) DiagnosticLog.record("ERROR", "TUN_SESSION", failure.stackTraceToString(), sessionId)
        transport.close()
        connection.scope.cancel()
        synchronized(interfaceLock) {
            activeAddresses = emptySet()
            runCatching { monitor?.close() }
        }
        service.onSessionEnded(this, failure)
    }

    private fun unsigned(address: Int) = address.toLong() and 0xffffffffL

    private fun requireUsableDefault(lease: NativeTunIpv4Lease, localSubnet: IPv4Cidr) {
        val route = requireNotNull(lease.routes.firstOrNull { it.prefixLength == 0 }) {
            service.getString(R.string.network_runtime_error_dhcp_no_default_route)
        }
        // A classless default with gateway 0 explicitly marks its destinations as on-link.
        if (route.gateway == 0) return
        val gateway = unsigned(route.gateway)
        val onLink = if (localSubnet.contains(gateway)) {
            !localSubnet.isBroadcast(gateway) && (localSubnet.prefix >= 31 || gateway != localSubnet.network)
        } else {
            lease.routes.any { item ->
                item.gateway == 0 &&
                    IPv4Cidr.of(unsigned(item.destination), item.prefixLength).contains(gateway)
            }
        }
        require(gateway != unsigned(lease.address) && isUnicastIPv4(gateway) && onLink) {
            service.getString(R.string.network_runtime_error_dhcp_gateway_unreachable)
        }
    }
}
