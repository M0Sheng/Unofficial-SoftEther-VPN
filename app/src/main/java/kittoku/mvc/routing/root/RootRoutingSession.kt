package kittoku.mvc.routing.root

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Looper
import android.os.Process
import android.system.Os
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.nativecore.RootAccess
import kittoku.mvc.network.PhysicalUnderlayLostException
import kittoku.mvc.routing.AppRoutingConfiguration
import kittoku.mvc.routing.AppRoutingMode
import kittoku.mvc.routing.RootBypassPlan
import kittoku.mvc.routing.RootRoutingHelper
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStreamWriter
import java.net.NetworkInterface
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** One root-owned guardian serializes UID defaults, owned TAP rules, and journal recovery. */
internal class RootRoutingSession private constructor(
    private val context: Context,
    private val sessionId: String,
    private val underlay: Network,
    private val configuration: AppRoutingConfiguration,
    private val bypassPlan: RootBypassPlan,
    private val tapInterfaceName: String,
    private val onFailure: (Throwable) -> Unit,
) : AutoCloseable {
    private val manager = context.getSystemService(ConnectivityManager::class.java)
    private val lifecycle = Any()
    private val writeLock = Any()
    private val closed = AtomicBoolean(false)
    private val failed = AtomicBoolean(false)
    private val ready = CompletableFuture<Unit>()
    private val acceptingConfiguration = CompletableFuture<Unit>()
    private val packageSnapshot = CompletableFuture<List<RootPackageEntry>>()
    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "root-routing-attach").also { it.isDaemon = true }
    }
    private var process: java.lang.Process? = null
    private var output: BufferedWriter? = null
    @Volatile private var configurationFile: File? = null
    private var callbackRegistered = false
    private var receiverRegistered = false
    @Volatile private var attachedNetwork: Network? = null
    @Volatile private var ownedTapIndex: Int? = null
    @Volatile private var initialUnderlayRoutes: String? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (network == underlay && initialUnderlayRoutes != routeSignature(properties)) {
                fail(PhysicalUnderlayLostException(messageRes = R.string.route_error_root_underlay_routes_changed))
                return
            }
            if (properties.interfaceName == tapInterfaceName) attach(network)
        }
        override fun onLost(network: Network) {
            if (network == underlay) fail(PhysicalUnderlayLostException(network))
            else if (network == attachedNetwork) fail(IOException(appText(R.string.route_error_root_route_network_changed)))
        }
    }
    private val packages = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val uid = intent.getIntExtra(Intent.EXTRA_UID, -1)
            if (uid < 0 || uid / 100000 == Process.myUid() / 100000) {
                fail(IOException(appText(R.string.route_error_root_app_state_changed)))
            }
        }
    }

    private fun initialize() {
        check(Looper.myLooper() != Looper.getMainLooper()) { appText(R.string.route_error_root_routes_background) }
        val caps = manager.getNetworkCapabilities(underlay) ?: throw PhysicalUnderlayLostException(underlay, R.string.route_error_underlay_lost)
        require(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) { appText(R.string.route_error_root_route_underlay_transport) }
        val underlayProperties = manager.getLinkProperties(underlay) ?: throw IOException(appText(R.string.route_error_underlay_interface))
        val iface = underlayProperties.interfaceName ?: throw IOException(appText(R.string.route_error_underlay_interface))
        require(iface != tapInterfaceName) { appText(R.string.route_error_adapter_underlay_interface) }
        initialUnderlayRoutes = routeSignature(underlayProperties)
        val directory = privateDirectory(context)
        val privateEntries = directory.list() ?: throw IOException(appText(R.string.route_error_root_route_recovery_dir))
        if (configuration.mode == AppRoutingMode.ALL && bypassPlan.cidrs.isEmpty() && "journal.v1" !in privateEntries) {
            ready.complete(Unit)
            releaseOwner()
            worker.shutdown()
            return
        }
        prepareFiles(directory)
        require(manager.allNetworks.none { manager.getLinkProperties(it)?.interfaceName == tapInterfaceName }) {
            appText(R.string.route_error_previous_adapter)
        }
        val userId = Process.myUid() / 100000
        val packageParser = RootPackageSnapshotParser(userId)
        val classPath = context.applicationInfo.sourceDir + ":/system/framework/services.jar"
        val command = "exec env CLASSPATH=${quote(classPath)} /system/bin/app_process /system/bin ${RootRoutingHelper::class.java.name} --directory ${quote(directory.path)} --user $userId"
        val child = synchronized(lifecycle) {
            check(!closed.get()) { appText(R.string.route_error_root_session_cancelled) }
            RootAccess.start(command).also {
                process = it
                output = BufferedWriter(OutputStreamWriter(it.outputStream, Charsets.UTF_8))
            }
        }
        Thread({
            try {
                child.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.forEach { line ->
                        if (line.length > 131072) throw IOException(appText(R.string.route_error_root_route_log_limit))
                        if (packageParser.consume(line)) {
                            if (packageParser.complete) {
                                val snapshot = packageParser.snapshot()
                                packageSnapshot.complete(snapshot)
                                DiagnosticLog.record("INFO", "ROOT_ROUTING", "Root package snapshot received user=$userId count=${snapshot.size}; package inventory omitted from diagnostic log", sessionId)
                            }
                            return@forEach
                        }
                        DiagnosticLog.record("DEBUG", "ROOT_ROUTING", line, sessionId)
                        if (line == "READY_FOR_CONFIG") acceptingConfiguration.complete(Unit)
                        if (line.startsWith("READY_INITIAL ")) {
                            configurationFile = null // Helper read and unlinked only this session's UUID file.
                            ready.complete(Unit)
                        }
                    }
                }
            } catch (error: Throwable) {
                ready.completeExceptionally(error)
                acceptingConfiguration.completeExceptionally(error)
                packageSnapshot.completeExceptionally(error)
                if (!closed.get()) fail(error)
            }
        }, "root-routing-stdout").also { it.isDaemon = true; it.start() }
        Thread({
            runCatching { child.errorStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.forEach { DiagnosticLog.record("WARN", "ROOT_ROUTING", it.take(131072), sessionId) }
            } }
        }, "root-routing-stderr").also { it.isDaemon = true; it.start() }
        Thread({
            val code = child.waitFor()
            val error = IOException(appText(R.string.route_error_root_daemon_stopped, code))
            ready.completeExceptionally(error)
            acceptingConfiguration.completeExceptionally(error)
            packageSnapshot.completeExceptionally(error)
            if (!closed.get()) fail(error)
            releaseOwner()
        }, "root-routing-wait").also { it.isDaemon = true; it.start() }
        val initializationDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        acceptingConfiguration.get(30, TimeUnit.SECONDS)
        val installed = packageSnapshot.get(1, TimeUnit.SECONDS).associate { it.packageName to it.uid }
        require(installed[context.packageName] == Process.myUid()) { appText(R.string.route_error_root_packages_app_uid) }
        val plan = RootUidPlanner.plan(configuration, installed, Process.myUid())
        DiagnosticLog.record("INFO", "ROOT_ROUTING", "Preparing UID defaults ranges=${plan.bypassRanges.size} missing_packages=${plan.missingPackages.size} shared_uid_packages=${plan.sharedUidPackages.size} cidrs=${bypassPlan.cidrs.size}; current-user ordinary IP sockets only; system link control unchanged", sessionId)
        if (plan.sharedUidPackages.isNotEmpty()) DiagnosticLog.record("WARN", "ROOT_ROUTING", "Shared UID applies to packages=${plan.sharedUidPackages.sorted().joinToString()}", sessionId)
        val wire = RootRoutingWire.initial(Process.myUid(), networkId(underlay), iface,
            UUID.randomUUID().toString(), plan.bypassRanges, bypassPlan.cidrs, tapInterfaceName)
        val privateConfiguration = writeInitialFile(directory, wire)
        configurationFile = privateConfiguration
        if (closed.get()) { runCatching { privateConfiguration.delete() }; throw IOException(appText(R.string.route_error_root_session_cancelled)) }
        // Root has finished authorization/recovery and is already reading stdin before any write.
        worker.execute { try { send("INIT_FILE\t${privateConfiguration.name}") } catch (error: Throwable) { ready.completeExceptionally(error); fail(error) } }
        val remaining = initializationDeadline - System.nanoTime()
        if (remaining <= 0L) throw IOException(appText(R.string.route_error_root_initialization_timeout))
        ready.get(remaining, TimeUnit.NANOSECONDS)
        synchronized(lifecycle) {
            check(!closed.get()) { appText(R.string.route_error_root_session_cancelled) }
            val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
            manager.registerNetworkCallback(request, callback)
            callbackRegistered = true
            if (configuration.mode != AppRoutingMode.ALL) {
                val filter = IntentFilter().apply {
                    addAction(Intent.ACTION_PACKAGE_ADDED); addAction(Intent.ACTION_PACKAGE_REMOVED)
                    addAction(Intent.ACTION_PACKAGE_CHANGED); addDataScheme("package")
                }
                context.registerReceiver(packages, filter, Context.RECEIVER_NOT_EXPORTED)
                receiverRegistered = true
            }
        }
        if (manager.getNetworkCapabilities(underlay) == null) throw PhysicalUnderlayLostException(underlay, R.string.route_error_root_underlay_lost_setup)
        manager.allNetworks.forEach { network -> if (manager.getLinkProperties(network)?.interfaceName == tapInterfaceName) attach(network) }
        DiagnosticLog.record("WARN", "ROOT_ROUTING", "UID default-network/DNS policy ready; explicit owned TAP socket bypass waits for creation proof interface=$tapInterfaceName. Explicit Network DNS, isolated UIDs and privileged raw Ethernet sockets are not equivalent to VpnService per-app policy; existing sockets require reconnect", sessionId)
    }

    /** Called only after the native owner reports a verified exclusive TAP creation. */
    fun attachOwnedTap(ifIndex: Int) {
        if (closed.get()) return
        if (ifIndex <= 0) { fail(IOException(appText(R.string.route_error_adapter_generation_missing))); return }
        synchronized(lifecycle) {
            if (closed.get()) return
            val previous = ownedTapIndex
            if (previous != null && previous != ifIndex) {
                fail(IOException(appText(R.string.route_error_adapter_generation_changed)))
                return
            }
            ownedTapIndex = ifIndex
        }
        // Either the creation event or ConnectivityManager callback may arrive first.
        try {
            manager.allNetworks.forEach { network ->
                if (manager.getLinkProperties(network)?.interfaceName == tapInterfaceName) attach(network)
            }
        } catch (error: Throwable) { fail(error) }
    }

    private fun attach(network: Network) {
        if (closed.get()) return
        synchronized(lifecycle) {
            if (closed.get() || worker.isShutdown) return
            worker.execute {
                try {
                    if (closed.get()) return@execute
                    val properties = manager.getLinkProperties(network) ?: return@execute
                    if (properties.interfaceName != tapInterfaceName) return@execute
                    val index = ownedTapIndex ?: return@execute
                    if (NetworkInterface.getByName(tapInterfaceName)?.index != index) throw IOException(appText(R.string.route_error_adapter_changed))
                    if (network == underlay) throw IOException(appText(R.string.route_error_adapter_underlay_network))
                    attachedNetwork?.let { if (it != network) throw IOException(appText(R.string.route_error_adapter_network_changed)) }
                    if (attachedNetwork == network) return@execute
                    attachedNetwork = network
                    send(RootRoutingWire.attach(networkId(network), index, tapInterfaceName))
                } catch (error: Throwable) { fail(error) }
            }
        }
    }

    private fun send(line: String) {
        val writer = synchronized(lifecycle) {
            check(!closed.get()) { appText(R.string.route_error_root_session_closed) }
            checkNotNull(output)
        }
        synchronized(writeLock) {
            check(!closed.get()) { appText(R.string.route_error_root_session_closed) }
            writer.write(line); writer.newLine(); writer.flush()
        }
    }

    private fun fail(error: Throwable) {
        if (closed.get() || !failed.compareAndSet(false, true)) return
        DiagnosticLog.record("ERROR", "ROOT_ROUTING", error.stackTraceToString(), sessionId)
        // Caller performs its own bridge/session identity check; callback is on a worker thread.
        try { if (!closed.get()) onFailure(error) } finally { close() }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        synchronized(lifecycle) {
            if (callbackRegistered) runCatching { manager.unregisterNetworkCallback(callback) }
            callbackRegistered = false
            if (receiverRegistered) runCatching { context.unregisterReceiver(packages) }
            receiverRegistered = false
            val writer = output; output = null
            val privateConfiguration = configurationFile; configurationFile = null
            // Closing a Java buffered pipe can wait for a concurrent write. Never do this under
            // the lifecycle lock or the caller's thread; owner remains held until root truly exits.
            if (writer != null || privateConfiguration != null) Thread({
                runCatching { privateConfiguration?.delete() }
                runCatching { writer?.close() }
            }, "root-routing-stdin-close").also { it.isDaemon = true; it.start() }
            worker.shutdownNow()
            // Root watches stdin EOF and cleans its journal. Do not destroy su and orphan its child.
            if (process == null) releaseOwner()
        }
    }

    private fun releaseOwner() = synchronized(ownerMonitor) {
        if (owner === this) { owner = null; ownerMonitor.notifyAll() }
    }

    companion object {
        private val ownerMonitor = Object()
        private var owner: RootRoutingSession? = null

        fun start(context: Context, sessionId: String, underlyingNetwork: Network,
                  configuration: AppRoutingConfiguration, bypassPlan: RootBypassPlan,
                  tapInterfaceName: String,
                  onFailure: (Throwable) -> Unit): RootRoutingSession {
            RootRoutingWire.validateTapName(tapInterfaceName)
            val session = RootRoutingSession(context.applicationContext, sessionId, underlyingNetwork, configuration, bypassPlan, tapInterfaceName, onFailure)
            synchronized(ownerMonitor) {
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
                while (owner != null) {
                    if (System.nanoTime() > deadline) throw IOException(appText(R.string.route_error_root_session_previous_cleanup))
                    ownerMonitor.wait(100)
                }
                owner = session
            }
            try { session.initialize(); return session }
            catch (error: Throwable) { session.close(); throw error }
        }

        private fun privateDirectory(context: Context): File {
            val directory = File(context.filesDir.canonicalFile, "root-routing")
            require(directory.canonicalFile == directory && (directory.isDirectory || directory.mkdir())) { appText(R.string.route_error_root_route_directory) }
            Os.chmod(directory.path, 448)
            return directory
        }

        private fun prepareFiles(directory: File) {
            listOf("owner.lock", "journal.v1").forEach { name ->
                val file = File(directory, name)
                require(file.canonicalFile == file && (!file.exists() || file.isFile)) { appText(R.string.route_error_root_route_symlink) }
                if (!file.exists()) check(file.createNewFile()) { appText(R.string.route_error_root_route_private_file) }
                Os.chmod(file.path, 384)
            }
        }

        private fun writeInitialFile(directory: File, wire: String): File {
            val bytes = wire.toByteArray(Charsets.UTF_8)
            require(bytes.isNotEmpty() && bytes.size <= 131072) { appText(R.string.route_error_root_route_configuration_limit) }
            val file = File(directory, "init-${UUID.randomUUID()}.cfg")
            require(file.canonicalFile == file && file.createNewFile()) { appText(R.string.route_error_root_route_session_file) }
            try {
                Os.chmod(file.path, 384)
                FileOutputStream(file).use { stream -> stream.write(bytes); stream.fd.sync() }
                return file
            } catch (error: Throwable) {
                runCatching { file.delete() }
                throw error
            }
        }

        private fun networkId(network: Network): Int = network.toString().toIntOrNull()?.takeIf { it in 100..65535 }
            ?: throw IOException(appText(R.string.route_error_android_network_id))
        private fun routeSignature(properties: LinkProperties): String = properties.interfaceName.orEmpty() + ":" +
            properties.routes.map { it.toString() }.sorted().joinToString(";")
        private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
    }
}
