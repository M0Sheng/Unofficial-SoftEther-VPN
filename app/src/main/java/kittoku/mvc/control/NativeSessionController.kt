package kittoku.mvc.control

import android.net.ConnectivityManager
import android.net.Network
import android.os.SystemClock
import kittoku.mvc.R
import kittoku.mvc.nativecore.ManagedTapIdentity
import kittoku.mvc.nativecore.ManagedTapName
import kittoku.mvc.nativecore.NativeCoreRunner
import kittoku.mvc.nativecore.NativeRemoteManagementSettings
import kittoku.mvc.nativecore.RootAccess
import kittoku.mvc.nativecore.TapTlsPreflight
import kittoku.mvc.network.PhysicalUnderlayLostException
import kittoku.mvc.network.physicalUnderlays
import kittoku.mvc.routing.AppRoutingSettings
import kittoku.mvc.routing.RootBypassSettings
import kittoku.mvc.routing.root.RootRoutingSession
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.NetworkInterface
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** TLS identity is verified before giving credentials to the official native engine. */
internal class NativeSessionController(private val bridge: ConnectionContext) {
    private val closed = AtomicBoolean(false)
    @Volatile private var runner: NativeCoreRunner? = null
    @Volatile private var rootRouting: RootRoutingSession? = null
    @Volatile private var networkObserver: NetworkStatusMonitor? = null
    private val probe = AtomicReference<TapTlsPreflight?>()
    private var previousReceived = 0L
    private var previousSent = 0L
    private val sessionId = bridge.sessionId

    val interfaceName: String?
        get() = if (closed.get()) null else runner?.currentTapName()

    fun refreshStatus(): Boolean {
        val observer = networkObserver ?: return false
        observer.refresh()
        return true
    }

    fun run() {
        bridge.scope.launch(bridge.handler) {
            if (closed.get()) return@launch
            val managementOnly = bridge.nativeManagementOnly
            var coreStarted = false
            try {
                RootAccess.requireGranted()
                ensureActive()
                if (closed.get()) return@launch
                val pem = if (managementOnly) {
                    bridge.underlyingNetwork = selectUnderlyingNetwork()
                    null
                } else {
                    bridge.service.updateConnectionStatus(bridge, bridge.service.getString(R.string.network_runtime_status_verifying_server_certificate))
                    val preflight = TapTlsPreflight(
                        bridge.service.getSystemService(ConnectivityManager::class.java),
                        onNetworkLost = { network -> kill(PhysicalUnderlayLostException(network)) },
                    ) { level, tag, message -> DiagnosticLog.record(level, tag, message, sessionId) }
                    probe.set(preflight)
                    if (closed.get()) return@launch
                    val verified = preflight.verify(
                        bridge.serverHostname, bridge.serverPort, bridge.certificateSha256, bridge.sslVersion,
                        bridge.cipherSuites, bridge.excludedUnderlay,
                    )
                    bridge.underlyingNetwork = verified.network
                    verified.certificatePem
                }
                ensureActive()
                if (closed.get()) return@launch
                val network = bridge.underlyingNetwork ?: throw IOException(bridge.service.getString(R.string.network_runtime_error_underlay_unavailable))
                val tapName = selectTapName()
                val bypass = RootBypassSettings(bridge.service).resolveForRoot(
                    network, sessionId, requireNotNull(bridge.destinationConfiguration), bridge.forwardIpv6,
                )
                val routing = RootRoutingSession.start(bridge.service, sessionId, network,
                    AppRoutingSettings(bridge.service).load(), bypass, tapName) { error ->
                    if (!closed.get()) kill(error)
                }
                rootRouting = routing
                if (closed.get()) { routing.close(); return@launch }
                val remote = NativeRemoteManagementSettings(bridge.service)
                if (remote.enabled && !remote.hasPassword) {
                    throw IllegalArgumentException(bridge.service.getString(R.string.native_remote_password_required))
                }
                val native = NativeCoreRunner(bridge.service, NativeCoreRunner.Config(
                    underlyingNetworkHandle = network.networkHandle,
                    tapInterfaceName = tapName,
                    serverHostname = bridge.serverHostname, serverPort = bridge.serverPort,
                    hub = bridge.serverHubName, username = bridge.clientUsername, authentication = bridge.authentication,
                    verifiedLeafPem = pem, autoProvision = !managementOnly,
                    certificateSha256 = bridge.certificateSha256,
                    ipv6Enabled = bridge.forwardIpv6, sessionId = sessionId,
                    remoteManagementEnabled = remote.enabled,
                    remotePasswordHashFile = if (remote.enabled) remote.passwordHashFilePath else null,
                ), object : NativeCoreRunner.Callbacks {
                    override fun onStatus(message: String) {
                        if (!closed.get()) bridge.service.updateConnectionStatus(bridge, message)
                    }
                    override fun onTapCreated(interfaceName: String, ifIndex: Int) {
                        if (!closed.get() && interfaceName == tapName) routing.attachOwnedTap(ifIndex)
                    }
                    override fun onSecurityChanged() {
                        if (!closed.get() && runner?.connectionSecurity != null) networkObserver?.refresh()
                    }
                    override fun onReady(interfaceName: String, ifIndex: Int) {
                        if (closed.get()) return
                        closeNetworkObserver()
                        try {
                            val identity = ManagedTapIdentity(interfaceName, ifIndex)
                            val observer = NetworkStatusMonitor(bridge, tap = true,
                                owns = { it.interfaceName == identity.name && identity.isCurrent() },
                                statusDetails = { listOf(bridge.service.getString(R.string.network_runtime_network_details_transport), "SoftEther") },
                                connectionSecurity = { runner?.connectionSecurity })
                            networkObserver = observer
                            if (closed.get()) { closeNetworkObserver(); return }
                            bridge.service.onNativeSessionConnected(this@NativeSessionController)
                        } catch (error: RuntimeException) {
                            kill(error)
                        }
                    }
                    override fun onAccountDisconnected() {
                        closeNetworkObserver()
                        if (!closed.get()) bridge.service.onNativeManagedAccountDisconnected(this@NativeSessionController)
                    }
                    override fun onStopped(error: Throwable?) {
                        runCatching { rootRouting?.close() }
                        if (!closed.get()) kill(error ?: IOException(bridge.service.getString(R.string.network_runtime_error_tap_client_stopped)))
                    }
                    override fun onTraffic(received: Long, sent: Long) = countTraffic(received, sent)
                })
                runner = native
                if (closed.get()) { native.stop(); return@launch }
                // Keep the selected underlay, which may be non-default, until the core retains it.
                native.start(::closeProbe)
                coreStarted = true
                if (managementOnly) bridge.service.onNativeManagementStarted(this@NativeSessionController)
            } finally {
                if (!coreStarted) closeProbe()
            }
        }
    }

    private fun closeProbe() {
        runCatching { probe.getAndSet(null)?.close() }
    }

    private fun closeNetworkObserver() {
        val observer = networkObserver
        networkObserver = null
        observer?.close()
    }

    private suspend fun selectTapName(): String {
        val manager = bridge.service.getSystemService(ConnectivityManager::class.java)
        val previous = ManagedTapIdentity.previous(bridge.service)
        val deadline = SystemClock.elapsedRealtime() + 18_000L
        var waiting = false
        fun systemNetworkNames() = manager.allNetworks.mapNotNull { manager.getLinkProperties(it)?.interfaceName }.toSet()
        while (previous != null) {
            val current = NetworkInterface.getByName(previous.name)
            // A reused name with a different index belongs to a different device.
            val releasing = current?.index == previous.index ||
                (current == null && previous.name in systemNetworkNames())
            if (!releasing) break
            if (SystemClock.elapsedRealtime() >= deadline) {
                throw IOException(bridge.service.getString(R.string.network_runtime_error_previous_adapter_not_released))
            }
            if (!waiting) {
                DiagnosticLog.record("INFO", "NETWORK", "Waiting for ${previous.name} index=${previous.index} to be released", sessionId)
                bridge.service.updateConnectionStatus(bridge, bridge.service.getString(R.string.network_runtime_status_previous_adapter_releasing))
                waiting = true
            }
            delay(200L)
        }
        val occupied = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().map { it.name }.toSet() + systemNetworkNames()
        return ManagedTapName.select(bridge.service, occupied)
    }

    private fun selectUnderlyingNetwork(): Network {
        val manager = bridge.service.getSystemService(ConnectivityManager::class.java)
        return manager.physicalUnderlays().firstOrNull()?.network
            ?: throw IOException(bridge.service.getString(R.string.network_runtime_error_enable_underlay_network))
    }

    @Synchronized private fun countTraffic(received: Long, sent: Long) {
        if (closed.get() || received < 0 || sent < 0) return
        TrafficMeter.markAvailable(sessionId)
        TrafficMeter.received(sessionId, if (received >= previousReceived) received - previousReceived else received)
        TrafficMeter.sent(sessionId, if (sent >= previousSent) sent - previousSent else sent)
        previousReceived = received; previousSent = sent
    }

    fun kill(error: Throwable?) {
        if (!closed.compareAndSet(false, true)) return
        if (error != null) DiagnosticLog.record("ERROR", "NATIVE_SESSION", error.stackTraceToString(), sessionId)
        runCatching { runner?.stop() }
        // A running core retains policy until its owned TAP/processes actually exit.
        if (runner == null) runCatching { rootRouting?.close() }
        closeProbe()
        closeNetworkObserver()
        bridge.service.onNativeSessionEnded(this, error)
        bridge.scope.cancel()
    }
}
