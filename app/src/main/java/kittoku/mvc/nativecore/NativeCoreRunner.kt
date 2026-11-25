package kittoku.mvc.nativecore

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.system.Os
import android.util.Base64
import kittoku.mvc.i18n.appText
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.network.PhysicalUnderlayLostException
import kittoku.mvc.network.physicalUnderlay
import kittoku.mvc.cipher.hashSha0
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Default official Cedar/Mayaqua process; the separate non-root TUN backend is retained. */
internal class NativeCoreRunner(context: Context, val config: Config, private val callbacks: Callbacks) {
    data class Config(
        val underlyingNetworkHandle: Long,
        val tapInterfaceName: String,
        val serverHostname: String,
        val serverPort: Int,
        val hub: String,
        val username: String,
        val authentication: NativeAuthentication,
        val verifiedLeafPem: ByteArray? = null,
        val autoProvision: Boolean = true,
        val ipv6Enabled: Boolean,
        val sessionId: String = "",
        val enableUdpAcceleration: Boolean = false,
        val remoteManagementEnabled: Boolean = false,
        val remotePasswordHashFile: String? = null,
        val certificateSha256: String = "",
    )
    interface Callbacks {
        fun onStatus(message: String)
        fun onTapCreated(interfaceName: String, ifIndex: Int)
        fun onReady(interfaceName: String, ifIndex: Int)
        fun onAccountDisconnected()
        fun onStopped(error: Throwable?)
        fun onSecurityChanged() {}
        /** Cumulative official account counters; absence of a callback means unknown. */
        fun onTraffic(received: Long, sent: Long) {}
    }
    data class CommandResult(val exitCode: Int, val output: String)
    class NativeCommandException(message: String) : IllegalStateException(message)

    private val app = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val closed = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private val lifecycleLock = Any()
    private val commandLock = Any()
    private val networkLock = Any()
    private val processes = mutableSetOf<Process>()
    private val manager = app.getSystemService(ConnectivityManager::class.java)
    private val dataDir = File(app.filesDir, "official-native-core")
    private val runId = UUID.randomUUID().toString()
    private val secretFile = File(dataDir, "management-$runId.secret")
    private val certificateFile = File(dataDir, "verified-server-$runId.pem")
    private val clientBinary = File(app.applicationInfo.nativeLibraryDir, "libhomevpn_vpnclient.so")
    private val commandBinary = File(app.applicationInfo.nativeLibraryDir, "libhomevpn_vpncmd.so")
    @Volatile private var ownerThread: Thread? = null
    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var managementReady = false
    @Volatile private var createdTap: ManagedTapIdentity? = null
    @Volatile var connectionSecurity: NativeConnectionSecurity? = null
        get() = if (closed.get()) null else field
        private set
    private var managementSecret = ""

    fun ownsTapInterface(name: String, index: Int): Boolean = !closed.get() &&
        createdTap?.let { it.name == name && it.index == index } == true

    fun currentTapName(): String? {
        if (closed.get()) return null
        val tap = createdTap ?: return null
        return tap.name.takeIf { runCatching(tap::isCurrent).getOrDefault(false) }
    }

    fun start(onUnderlayRetained: () -> Unit) = synchronized(lifecycleLock) {
        checkOpen()
        check(started.compareAndSet(false, true)) { app.getString(R.string.network_runtime_error_tap_session_already_started) }
        Thread({
            try { runSession(onUnderlayRetained) } catch (error: Throwable) { finish(error) }
        }, "homevpn-native-owner").also { it.isDaemon = true; ownerThread = it; it.start() }
        Unit
    }

    /** Every native process watches our stdin pipe and terminates its own PID on EOF. */
    fun stop() = finish(null)

    private fun runSession(onUnderlayRetained: () -> Unit) {
        claimOwner()
        require(Build.VERSION.SDK_INT >= 36) { app.getString(R.string.network_runtime_error_android_version_required) }
        check(clientBinary.isFile && commandBinary.isFile) { app.getString(R.string.network_runtime_error_tap_core_missing) }
        if (config.remoteManagementEnabled) {
            val hashFile = File(requireNotNull(config.remotePasswordHashFile) { app.getString(R.string.native_remote_password_required) }).canonicalFile
            require(hashFile.path.startsWith(app.filesDir.canonicalPath + File.separator)) { app.getString(R.string.network_runtime_error_remote_password_directory) }
            require(hashFile.isFile && hashFile.length() == 20L && isUsableRemoteHash(hashFile.readBytes())) { app.getString(R.string.network_runtime_error_remote_password_invalid) }
            Os.chmod(hashFile.path, 384)
        }
        require(config.underlyingNetworkHandle != 0L) { app.getString(R.string.network_runtime_error_underlay_required) }
        require(ManagedTapName.isValid(config.tapInterfaceName)) { app.getString(R.string.network_runtime_error_virtual_adapter_name_invalid) }
        if (config.autoProvision) {
            require(config.verifiedLeafPem != null && config.verifiedLeafPem.isNotEmpty()) { app.getString(R.string.network_runtime_error_server_verification_required) }
            require(config.serverPort in 1..65535 && config.serverHostname.isNotBlank()) { app.getString(R.string.network_runtime_error_server_endpoint_invalid) }
            require(config.hub.isNotBlank() && config.username.isNotBlank()) { app.getString(R.string.network_runtime_error_missing_hub_and_username) }
        }
        keepUnderlyingNetwork()
        onUnderlayRetained()
        checkOpen()
        awaitUnoccupiedManagementPort()
        if (NetworkInterface.getByName(config.tapInterfaceName) != null) {
            throw IOException(app.getString(R.string.network_runtime_error_tap_name_in_use))
        }
        check(dataDir.mkdirs() || dataDir.isDirectory) { app.getString(R.string.network_runtime_error_tap_data_directory) }
        Os.chmod(dataDir.path, 448) // 0700
        managementSecret = ByteArray(48).also(SecureRandom()::nextBytes).let {
            Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        }
        writePrivate(secretFile, managementSecret.toByteArray(Charsets.US_ASCII))
        replaceRuntimeFile("hamcore.se2") { temporary ->
            app.assets.open("native-core/hamcore.se2").use { input ->
                temporary.outputStream().use { output -> input.copyTo(output) }
            }
        }
        replaceRuntimeFile("lang.config") { it.writeBytes("en\n".toByteArray()) }
        status(app.getString(R.string.network_runtime_status_starting_tap))
        val process = spawn(rootCommand(listOf(clientBinary.path, "androidsvc"), bindUnderlay = true))
        Thread({
            runCatching {
                process.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.forEach(::handleNativeOutput)
                }
            }.onFailure { error ->
                if (!closed.get()) finish(IOException(error.message ?: app.getString(R.string.network_runtime_error_tap_creation_status), error))
            }
        }, "homevpn-native-output").also { it.isDaemon = true; it.start() }
        Thread({
            val code = process.waitFor()
            synchronized(lifecycleLock) { processes.remove(process) }
            if (!closed.get()) finish(IOException(app.getString(R.string.network_runtime_error_tap_client_exit, code)))
        }, "homevpn-native-wait").also { it.isDaemon = true; it.start() }
        var authenticated = false
        var firstProbeFailureLogged = false
        var lastProbeFailure = ""
        for (attempt in 0 until 40) {
            checkOpen()
            if (process.isAlive) {
                val outcome = runCatching { command("VersionGet", timeoutSeconds = 4) }
                val result = outcome.getOrNull()
                authenticated = result?.exitCode == 0 && result.output.contains("The command completed successfully.")
                if (!authenticated) {
                    lastProbeFailure = sanitize(outcome.exceptionOrNull()?.stackTraceToString()
                        ?: "exit=${result?.exitCode}\n${result?.output.orEmpty().takeLast(4_000)}")
                    if (!firstProbeFailureLogged) {
                        firstProbeFailureLogged = true
                        DiagnosticLog.record("DEBUG", "NATIVE_RPC_BOOTSTRAP", "Initial local RPC probe not ready:\n$lastProbeFailure", config.sessionId)
                    }
                }
            }
            if (authenticated) break
            Thread.sleep(250)
        }
        check(authenticated) { app.getString(R.string.network_runtime_error_tap_local_auth, lastProbeFailure.takeLast(1_800)) }
        synchronized(lifecycleLock) {
            checkOpen()
            managementReady = true
            active = this
        }
        if (!config.autoProvision) {
            status(app.getString(R.string.native_management_started))
        } else {
            val udpStatus = if (config.enableUdpAcceleration) R.string.network_runtime_status_tap_udp_allowed
                else R.string.network_runtime_status_tap_udp_disabled
            status(app.getString(udpStatus))
            provisionMainAccount()
        }
        if (config.autoProvision) {
            val started = System.nanoTime()
            val deadline = started + TimeUnit.SECONDS.toNanos(45)
            var connected = false
            var lastState = "phase=unavailable"
            while (!closed.get() && System.nanoTime() < deadline) {
                val result = command("AccountStatusGet home", csv = true)
                val state = csvRows(result.output)["Session Status"]
                connected = result.exitCode == 0 && state == "Connection Completed (Session Established)"
                if (DiagnosticLog.isCollectionEnabled()) {
                    val phase = if (result.exitCode == 0) nativeAccountPhase(state) else "rpc-error"
                    val nextState = "phase=$phase exit=${result.exitCode}"
                    if (nextState != lastState) {
                        val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                        DiagnosticLog.record("DEBUG", "NATIVE_SESSION_STATE",
                            "mode=TAP $nextState elapsed_ms=$elapsed", config.sessionId)
                        lastState = nextState
                    }
                }
                if (connected) break
                Thread.sleep(500)
            }
            if (!connected && !closed.get()) {
                val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                DiagnosticLog.record("WARN", "NATIVE_SESSION_STATE",
                    "mode=TAP outcome=timeout $lastState elapsed_ms=$elapsed", config.sessionId)
            }
            check(connected) { app.getString(R.string.network_runtime_error_tap_account_timeout) }
        }
        val securityReader = NativeConnectionSecurityReader(config.verifiedLeafPem, config.certificateSha256)
        var wasConnected: Boolean? = null
        while (!closed.get()) {
            val result = command("AccountStatusGet home", csv = true)
            val rows = csvRows(result.output)
            val connected = result.exitCode == 0 && rows["Session Status"] == "Connection Completed (Session Established)"
            val security = if (connected) securityReader.read(rows) else null
            if (security != connectionSecurity) {
                connectionSecurity = security
                main.post { if (!closed.get()) callbacks.onSecurityChanged() }
            }
            val received = byteCount(rows["Incoming Data Size"])
            val sent = byteCount(rows["Outgoing Data Size"])
            if (received != null && sent != null) main.post { if (!closed.get()) callbacks.onTraffic(received, sent) }
            if (connected && wasConnected != true) {
                val interfaceDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (createdTap?.isCurrent() != true && System.nanoTime() < interfaceDeadline) {
                    checkOpen()
                    Thread.sleep(100)
                }
                val tap = createdTap?.takeIf(ManagedTapIdentity::isCurrent)
                    ?: throw IOException(app.getString(R.string.network_runtime_error_tap_adapter_not_detected))
                checkOpen()
                status(app.getString(R.string.network_runtime_status_tap_android_configuring))
                main.post { if (!closed.get()) callbacks.onReady(tap.name, tap.index) }
            } else if (!connected && wasConnected == true && config.autoProvision) {
                // The native client publishes its terminal code before making the account inactive.
                // Give the output reader time to consume it before handling an external disconnect.
                Thread.sleep(500)
                checkOpen()
                throw IOException(app.getString(R.string.error_session_disconnected))
            } else if (!connected && wasConnected != false && !config.autoProvision) {
                if (wasConnected == true) main.post { if (!closed.get()) callbacks.onAccountDisconnected() }
                status(app.getString(R.string.native_management_server_disconnected))
            }
            wasConnected = connected
            Thread.sleep(2_000)
        }
    }

    private fun handleNativeOutput(line: String) {
        val failure = if (config.autoProvision) nativeSessionFailure(line) else null
        if (failure != null) {
            finish(failure)
            return
        }
        if (!line.startsWith(ManagedTapIdentity.CREATION_PREFIX)) {
            if (DiagnosticLog.isCollectionEnabled()) {
                DiagnosticLog.record(nativeOutputLevel(line), "NATIVE_CORE", sanitize(line), config.sessionId)
            }
            return
        }
        val tap = ManagedTapIdentity.parseCreation(line, runId, config.tapInterfaceName) ?: return
        if (closed.get() || createdTap == tap) return
        check(createdTap == null) { app.getString(R.string.network_runtime_error_tap_adapter_recreated) }
        check(tap.remember(app)) { app.getString(R.string.network_runtime_error_tap_adapter_identity_save) }
        createdTap = tap
        DiagnosticLog.record("INFO", "NATIVE_CORE", "Created virtual adapter ${tap.name} index=${tap.index}", config.sessionId)
        if (!closed.get()) callbacks.onTapCreated(tap.name, tap.index)
    }

    private fun provisionMainAccount() {
        status(app.getString(R.string.network_runtime_status_tap_account_configuring))
        DiagnosticLog.record("INFO", "NATIVE_PROVISION", "mode=TAP ${config.authentication.diagnosticSummary}", config.sessionId)
        writePrivate(certificateFile, requireNotNull(config.verifiedLeafPem))
        val nics = provisioningCommand("NicList", csv = true)
        if (nics.exitCode != 0) throw NativeCommandException(app.getString(R.string.network_runtime_error_tap_adapter_list, sanitize(nics.output.takeLast(1800))))
        if (!nicListContains(nics.output, "home")) {
            val created = provisioningCommand("NicCreate home")
            if (created.exitCode == 30) { // Official ERR_VLAN_ALREADY_EXISTS: a concurrent administrator may have created it.
                val refreshed = provisioningCommand("NicList", csv = true)
                if (refreshed.exitCode != 0 || !nicListContains(refreshed.output, "home")) requireSuccess(created)
            } else {
                if (created.exitCode != 0 && createdTap == null && NetworkInterface.getByName(config.tapInterfaceName) != null) {
                    throw IOException(app.getString(R.string.network_runtime_error_tap_name_claimed))
                }
                requireSuccess(created)
            }
        }
        requireSuccess(provisioningCommand("NicEnable home"))
        val accounts = provisioningCommand("AccountGet home", csv = true)
        if (accounts.exitCode != 0) {
            requireSuccess(provisioningCommand("AccountCreate home /SERVER:${token(serverAuthority())} /HUB:${token(config.hub)} /USERNAME:${token(config.username)} /NICNAME:home"))
        } else {
            provisioningCommand("AccountDisconnect home")
            requireSuccess(provisioningCommand("AccountSet home /SERVER:${token(serverAuthority())} /HUB:${token(config.hub)}"))
            requireSuccess(provisioningCommand("AccountUsernameSet home /USERNAME:${token(config.username)}"))
        }
        // A previously saved account may have fallen back to the Unix default
        // NIC while home was absent. Rebind it explicitly after creating home.
        requireSuccess(provisioningCommand("AccountNicSet home /NICNAME:home"))
        config.authentication.provision(app.cacheDir, ::writePrivate) { script ->
            requireSuccess(provisioningCommand(script), confidential = true)
        }
        requireSuccess(provisioningCommand("AccountEncryptEnable home"))
        requireSuccess(provisioningCommand("AccountServerCertSet home /LOADCERT:${token(certificateFile.path)}"))
        requireSuccess(provisioningCommand("AccountServerCertEnable home"))
        requireSuccess(provisioningCommand("AccountStartupRemove home"))
        requireSuccess(provisioningCommand("AccountConnect home"))
    }

    private fun provisioningCommand(text: String, csv: Boolean = false): CommandResult =
        traceProvisioningCommand("TAP", config.sessionId, text.substringBefore(' ')) { command(text, csv) }

    /** Blocking; call from a worker. Input goes to vpncmd's command-file parser, never the shell. */
    fun executeAdvanced(commands: String): CommandResult {
        check(managementReady && !closed.get()) { app.getString(R.string.native_command_service_unavailable) }
        require(commands.isNotBlank() && !commands.contains('\u0000') && commands.length <= 32_768) { app.getString(R.string.network_runtime_error_tap_command_invalid) }
        val raw = command(commands, timeoutSeconds = 30)
        // vpncmd echoes command-file input and can prompt for additional secrets.
        // Console output is shown only to the requesting activity, never copied into diagnostics.
        DiagnosticLog.record(if (raw.exitCode == 0) "INFO" else "WARN", "NATIVE_COMMAND",
            "vpncmd batch finished; exit=${raw.exitCode}; output retained only in the command screen", config.sessionId)
        val submittedSecrets = Regex("(?i)/(?:password|passwd|secret|key)\\s*:\\s*(?:\"((?:\"\"|[^\"])*)\"|([^\\s]+))")
            .findAll(commands).map { (it.groups[1]?.value ?: it.groups[2]?.value.orEmpty()).replace("\"\"", "\"") }.toList()
        return CommandResult(raw.exitCode, sanitizeOutput(raw.output, listOf(managementSecret, config.authentication.password, config.username) + submittedSecrets))
    }

    private fun command(text: String, csv: Boolean = false, timeoutSeconds: Long = 12): CommandResult = synchronized(commandLock) {
        checkOpen()
        val input = File(dataDir, "command-$runId-${UUID.randomUUID()}.in")
        try {
            writePrivate(input, (text.trimEnd() + "\n").toByteArray(Charsets.UTF_8))
            // Official /CLIENT mode passes the target verbatim to CcConnectRpc,
            // which probes its fixed 9930..9934 ports; unlike /SERVER it does
            // not consume the separately parsed host:port value.
            val args = mutableListOf(commandBinary.path, "127.0.0.1", "/CLIENT", "/IN:${input.path}")
            if (csv) args += "/CSV"
            runRoot(rootCommand(args, connectionDetails = csv && text == "AccountStatusGet home"), timeoutSeconds)
        } finally { input.delete() }
    }

    /** Registration and close are atomic, so a stopped owner cannot start a late command. */
    private fun spawn(command: String): Process = synchronized(lifecycleLock) {
        checkOpen()
        RootAccess.start(command, mergeError = true).also { processes.add(it) }
    }

    private fun runRoot(command: String, timeoutSeconds: Long): CommandResult {
        val process = spawn(command)
        val output = StringBuilder()
        val reader = Thread({
            runCatching { process.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.forEach { line -> synchronized(output) { if (output.length < 512 * 1024) output.append(line).append('\n') } }
            } }
        }, "homevpn-native-command-output").also { it.isDaemon = true; it.start() }
        try {
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                // App UID cannot reliably signal a root child. Its own stdin watcher stops it.
                runCatching { process.outputStream.close() }
                if (!process.waitFor(20, TimeUnit.SECONDS)) throw NativeCommandException(app.getString(R.string.network_runtime_error_tap_command_process_alive))
                throw NativeCommandException(app.getString(R.string.network_runtime_error_tap_command_timeout))
            }
            reader.join(1_000)
            return CommandResult(process.exitValue(), synchronized(output) { output.toString() })
        } finally {
            runCatching { process.outputStream.close() }
            synchronized(lifecycleLock) { if (!process.isAlive) processes.remove(process) }
        }
    }

    private fun rootCommand(arguments: List<String>, bindUnderlay: Boolean = false, connectionDetails: Boolean = false): String {
        val environment = linkedMapOf("HOMEVPN_DATA_DIR" to dataDir.path, "HOMEVPN_ADMIN_SECRET_FILE" to secretFile.path, "LANG" to "C.UTF-8")
        if (connectionDetails) environment["HOMEVPN_CONNECTION_DETAILS"] = "1"
        if (bindUnderlay) {
            environment["HOMEVPN_UNDERLYING_NETWORK_HANDLE"] = java.lang.Long.toUnsignedString(config.underlyingNetworkHandle)
            environment["HOMEVPN_MANAGED_HOME"] = "1"
            environment["HOMEVPN_MANAGED_TAP"] = config.tapInterfaceName
            environment["HOMEVPN_TAP_TOKEN"] = runId
            environment["HOMEVPN_DEFER_STARTUP"] = "1"
            if (config.remoteManagementEnabled) {
                environment["HOMEVPN_REMOTE_MANAGEMENT_ENABLED"] = "1"
                environment["HOMEVPN_REMOTE_PASSWORD_HASH_FILE"] = File(requireNotNull(config.remotePasswordHashFile)).canonicalPath
            }
            if (!config.ipv6Enabled) environment["HOMEVPN_DISABLE_IPV6"] = "1"
            if (config.autoProvision) {
                environment["HOMEVPN_MANUAL_RETRY"] = "1"
                environment["HOMEVPN_EPHEMERAL_HOME_AUTH"] = "1"
                if (!config.enableUdpAcceleration) environment["HOMEVPN_DISABLE_UDP_ACCELERATION"] = "1"
            }
        }
        return rootInvocation(environment, arguments)
    }

    private fun keepUnderlyingNetwork() {
        val selected = Network.fromNetworkHandle(config.underlyingNetworkHandle)
        val caps = manager.getNetworkCapabilities(selected) ?: throw PhysicalUnderlayLostException(selected)
        val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> request.addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> request.addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            else -> throw IOException(app.getString(R.string.network_runtime_error_tap_underlay_required))
        }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                if (network == selected) finish(PhysicalUnderlayLostException(network))
            }
        }
        synchronized(networkLock) { checkOpen(); manager.requestNetwork(request.build(), callback); networkCallback = callback }
        if (manager.physicalUnderlay(selected) == null) throw PhysicalUnderlayLostException(selected)
    }

    private fun awaitUnoccupiedManagementPort() {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(18)
        while (System.nanoTime() < deadline) {
            checkOpen()
            val occupied = runCatching { Socket().use { it.connect(InetSocketAddress("127.0.0.1", 9930), 250) }; true }.getOrDefault(false)
            if (!occupied) return
            Thread.sleep(200)
        }
        throw NativeCommandException(app.getString(R.string.network_runtime_error_tap_management_port_in_use))
    }

    private fun claimOwner() = synchronized(ownerMonitor) {
        while (owner != null) { checkOpen(); ownerMonitor.wait(200) }
        checkOpen()
        owner = this
    }

    private fun finish(error: Throwable?) {
        synchronized(lifecycleLock) {
            if (!closed.compareAndSet(false, true)) return
            managementReady = false
            if (active === this) active = null
            processes.forEach { runCatching { it.outputStream.close() } }
        }
        synchronized(ownerMonitor) { ownerMonitor.notifyAll() }
        synchronized(networkLock) { networkCallback?.let { runCatching { manager.unregisterNetworkCallback(it) } }; networkCallback = null }
        if (error != null) DiagnosticLog.record("ERROR", "NATIVE_CORE", sanitize(error.stackTraceToString()), config.sessionId)
        Thread({
            // Joining the session worker also covers writes made just before stop and commands
            // holding commandLock. Never release the shared config directory while they can write.
            ownerThread?.join()
            val remaining = synchronized(lifecycleLock) { processes.toList() }
            val allExited = remaining.all { process ->
                runCatching { process.outputStream.close() }
                process.waitFor(20, TimeUnit.SECONDS)
            }
            val safeError = when {
                error is NativeSessionFailure -> error
                !allExited -> NativeCommandException(app.getString(R.string.network_runtime_error_previous_tap_process_alive))
                error is PhysicalUnderlayLostException -> error
                error is IOException -> IOException(sanitize(error.message ?: error.javaClass.simpleName))
                error != null -> NativeCommandException(sanitize(error.message ?: error.javaClass.simpleName))
                else -> null
            }
            if (allExited) {
                secretFile.delete()
                certificateFile.delete()
                synchronized(ownerMonitor) { if (owner === this) owner = null; ownerMonitor.notifyAll() }
            }
            // If a root process unexpectedly ignores EOF, retain the owner and fail closed.
            main.post { callbacks.onStopped(safeError) }
        }, "homevpn-native-cleanup").also { it.isDaemon = true; it.start() }
    }

    private fun requireSuccess(result: CommandResult, confidential: Boolean = false) {
        if (result.exitCode != 0 || !result.output.contains("The command completed successfully.")) {
            val detail = if (confidential) app.getString(R.string.network_runtime_tap_command_private_authentication) else sanitize(result.output.takeLast(1800))
            throw NativeCommandException(app.getString(R.string.network_runtime_error_tap_management_operation, result.exitCode, detail))
        }
    }
    private fun checkOpen() { if (closed.get()) throw NativeCommandException(app.getString(R.string.network_runtime_error_tap_session_closed)) }
    private fun status(message: String) {
        if (closed.get()) return
        DiagnosticLog.record("INFO", "NATIVE_CORE", sanitize(message), config.sessionId)
        main.post { if (!closed.get()) callbacks.onStatus(message) }
    }
    private fun serverAuthority() = (if (config.serverHostname.contains(':')) "[${config.serverHostname.removeSurrounding("[", "]")}]" else config.serverHostname) + ":${config.serverPort}"
    private fun writePrivate(file: File, bytes: ByteArray) { file.writeBytes(bytes); Os.chmod(file.path, 384) }

    /** A shutting-down daemon may still read the old runtime files. Publish complete replacements. */
    private fun replaceRuntimeFile(name: String, write: (File) -> Unit) {
        val temporary = File(dataDir, "$name-$runId.tmp")
        try {
            write(temporary)
            Os.chmod(temporary.path, 384)
            Os.rename(temporary.path, File(dataDir, name).path)
        } finally {
            temporary.delete()
        }
    }
    private fun sanitize(value: String): String = sanitizeOutput(value, listOf(managementSecret, config.authentication.password, config.username))

    companion object {
        private val ownerMonitor = Object()
        private var owner: NativeCoreRunner? = null
        @Volatile var active: NativeCoreRunner? = null
            private set
        internal fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
        internal fun rootInvocation(environment: Map<String, String>, arguments: List<String>): String {
            require(arguments.isNotEmpty() && arguments.none { it.contains('\u0000') }) { appText(R.string.network_runtime_error_native_arguments_invalid) }
            require(environment.keys.all { Regex("[A-Za-z_][A-Za-z0-9_]*").matches(it) } && environment.values.none { it.contains('\u0000') }) { appText(R.string.network_runtime_error_native_environment_invalid) }
            // env(1) treats any argument containing '=' as an assignment, even
            // quoted /data/app/~~random==/package==/lib/<abi>/executable paths.
            // The shell's explicit exec command has no such ambiguity.
            val exports = environment.entries.joinToString(" ") { (name, value) -> "$name=${shellQuote(value)}" }
            return (if (exports.isEmpty()) "" else "export $exports; ") + "exec " + arguments.joinToString(" ", transform = ::shellQuote)
        }
        internal fun isUsableRemoteHash(bytes: ByteArray): Boolean = bytes.size == 20 && bytes.any { it != 0.toByte() } &&
            !bytes.contentEquals(hashSha0(ByteArray(0)))
        internal fun token(value: String): String {
            require(value.none { it == '\u0000' || it == '\r' || it == '\n' }) { appText(R.string.network_runtime_error_command_parameter_invalid) }
            return "\"" + value.replace("\"", "\"\"") + "\""
        }
        internal fun sanitizeOutput(value: String, secrets: List<String>): String {
            var result = value.replace(Regex("(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"), "[PRIVATE KEY REDACTED]")
            result = result.lineSequence().joinToString("\n") { line ->
                if (Regex("(?i)session[ _-]*key|secure[ _-]*password|/password\\s*:|(?:^|[>\\s])PasswordSet(?:\\s|$)|management[ _-]*secret|client[ _-]*key|server[ _-]*key|cookie|bearer\\s+|authorization\\s*:").containsMatchIn(line)) "[SENSITIVE LINE REDACTED]" else line
            }
            secrets.filter(String::isNotEmpty).sortedByDescending(String::length).forEach { result = result.replace(it, "[REDACTED]") }
            return DiagnosticLog.sanitized(result)
        }
        internal fun nicListContains(text: String, name: String): Boolean = text.lineSequence().mapNotNull(::csvFields).any { fields ->
            // Official NicList CSV has exactly four columns; the adapter name
            // is first. Prompts and echoed private storage paths are not NIC rows.
            fields.size == 4 && fields[0].trim().equals(name, ignoreCase = true)
        }
        internal fun csvRows(text: String): Map<String, String> = text.lineSequence().mapNotNull(::csvFields).mapNotNull { fields ->
            if (fields.size == 2) fields[0].trim() to fields[1].trim() else null
        }.toMap()
        private fun csvFields(line: String): List<String>? {
            val fields = mutableListOf<String>(); val current = StringBuilder(); var quoted = false; var index = 0
            while (index < line.length) {
                val char = line[index]
                if (char == '"') {
                    if (quoted && index + 1 < line.length && line[index + 1] == '"') { current.append('"'); index++ }
                    else quoted = !quoted
                } else if (char == ',' && !quoted) { fields += current.toString(); current.setLength(0) }
                else current.append(char)
                index++
            }
            fields += current.toString()
            return if (quoted) null else fields
        }
        internal fun byteCount(value: String?): Long? = value?.let {
            Regex("^([0-9][0-9,]*)\\s+bytes$", RegexOption.IGNORE_CASE).find(it)?.groupValues?.get(1)?.replace(",", "")?.toLongOrNull()
        }
    }
}
