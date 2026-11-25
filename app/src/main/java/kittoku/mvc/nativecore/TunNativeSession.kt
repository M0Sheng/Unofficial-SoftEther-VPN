package kittoku.mvc.nativecore

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.system.Os
import io.github.m0sheng.unofficialsoftethervpn.link.FrameEndpoint
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.network.PhysicalUnderlayLostException
import kittoku.mvc.nativecore.NativeCoreRunner.Companion.token
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InterruptedIOException
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.security.SecureRandom
import java.util.Base64
import java.util.HexFormat
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Owns one unprivileged native client and its Ethernet channel. The caller owns the TUN and DHCP. */
internal class TunNativeSession(context: Context, private val config: Config, private val callbacks: Callbacks) :
    Closeable {
    data class Config(
        val serverHostname: String,
        val serverPort: Int,
        val hub: String,
        val username: String,
        val authentication: NativeAuthentication,
        val certificateSha256: String,
        val sslVersion: String,
        val cipherSuites: Set<String>?,
        val enableUdpAcceleration: Boolean,
        val ipv6Enabled: Boolean,
        val requestedMac: ByteArray,
        val sessionId: String,
        val excludedUnderlay: Network? = null,
    )

    /** Callbacks use the session worker. Start the lease and TUN workers separately from [onReady]. */
    interface Callbacks {
        fun onStatus(message: String)
        fun onReady(network: Network, endpoint: FrameEndpoint, mac: ByteArray)
        fun onStopped(error: Throwable)
        fun onSecurityChanged() {}
    }

    private val app = context.applicationContext
    private val adapterMac = config.requestedMac.copyOf()
    private val requestedCiphers = config.cipherSuites?.toSet()
    private val lock = Any()
    @Volatile private var stopping = false
    @Volatile var connectionSecurity: NativeConnectionSecurity? = null
        get() = if (stopping) null else field
        private set
    private var stopReason: Throwable? = null
    private var started = false
    private var owner: Thread? = null
    private var preflight: TapTlsPreflight? = null

    fun start() {
        synchronized(lock) {
            check(!started && !stopping) { app.getString(R.string.network_runtime_error_tun_session_wrong_state) }
            started = true
            owner = Thread(::runSession, "homevpn-tun-native").apply { isDaemon = true; start() }
        }
    }

    override fun close() = requestStop(null)

    fun connectionFailure(): Throwable? = synchronized(lock) {
        stopReason?.takeIf { it is NativeSessionFailure || it is PhysicalUnderlayLostException }
    }

    private fun requestStop(error: Throwable?) {
        val probe: TapTlsPreflight?
        val worker: Thread?
        synchronized(lock) {
            if (stopping) return
            stopReason = error
            stopping = true
            worker = owner
            probe = preflight
        }
        if (worker !== Thread.currentThread()) worker?.interrupt()
        probe?.let { runCatching(it::close) }
    }

    private fun runSession() {
        var workspace: Workspace? = null
        var daemon: Process? = null
        var output: Thread? = null
        var ethernet: FrameEndpoint? = null
        var failure: Throwable? = null
        try {
            require(config.serverPort in 1..65535 && config.serverHostname.isNotBlank()) { app.getString(R.string.network_runtime_error_server_endpoint_invalid) }
            require(config.hub.isNotBlank() && config.username.isNotBlank()) { app.getString(R.string.network_runtime_error_missing_hub_and_username) }
            require(validMac(adapterMac)) { app.getString(R.string.network_runtime_error_virtual_adapter_mac_unicast) }
            require(config.sslVersion in SUPPORTED_TLS) { app.getString(R.string.network_runtime_error_tun_tls_version_invalid) }
            require(requestedCiphers == null || requestedCiphers.isNotEmpty() &&
                requestedCiphers.all { TLS_CIPHER.matches(it) }) { app.getString(R.string.network_runtime_error_tun_tls_suites_invalid) }

            status(app.getString(R.string.network_runtime_status_verifying_server_certificate))
            val probe = TapTlsPreflight(app.getSystemService(ConnectivityManager::class.java), "TUN",
                { network -> requestStop(PhysicalUnderlayLostException(network)) }, ::record)
            synchronized(lock) {
                checkRunning()
                preflight = probe
            }
            val verified = probe.verify(config.serverHostname.removeSurrounding("[", "]"), config.serverPort,
                config.certificateSha256, config.sslVersion, requestedCiphers, config.excludedUnderlay)
            checkRunning()

            val port = ServerSocket(0, 1, LOOPBACK).use { it.localPort }
            val secret = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(ByteArray(48).also(SecureRandom()::nextBytes))
            val directory = Files.createTempDirectory(app.noBackupFilesDir.toPath(), "native-tun-").toFile()
            val files = Workspace(directory, port, secret).also { workspace = it }
            files.initialize(verified.certificatePem)

            status(app.getString(R.string.network_runtime_status_starting_tun))
            FrameEndpoint.listen().use { listener ->
                val child = files.launch("vpnclient", listOf("androidsvc"), mapOf(
                    FrameEndpoint.SOCKET_ENVIRONMENT to listener.name(),
                    "HOMEVPN_MANAGED_HOME" to "1",
                    "HOMEVPN_MANUAL_RETRY" to "1",
                    "HOMEVPN_EPHEMERAL_HOME_AUTH" to "1",
                    "HOMEVPN_REMOTE_MANAGEMENT_ENABLED" to "0",
                    "HOMEVPN_UNDERLYING_NETWORK_HANDLE" to
                        java.lang.Long.toUnsignedString(verified.network.networkHandle),
                    "HOMEVPN_FRAME_MAC" to HEX.formatHex(adapterMac),
                ) + nativeOptions())
                daemon = child
                ethernet = listener.accept(child)
            }
            val child = checkNotNull(daemon)
            val rpcReady = CountDownLatch(1)
            val readyMarker = "FRAME_RPC_READY=$port"
            output = Thread({
                try {
                    child.inputStream.bufferedReader(Charsets.UTF_8).forEachLine { line ->
                        if (line == readyMarker) {
                            rpcReady.countDown()
                        } else {
                            val failure = nativeSessionFailure(line)
                            if (failure != null) requestStop(failure)
                            else if (DiagnosticLog.isCollectionEnabled()) record(nativeOutputLevel(line), "TUN_NATIVE", files.sanitize(line))
                        }
                    }
                } catch (error: IOException) {
                    if (!stopping) record("WARN", "TUN_NATIVE", app.getString(R.string.network_runtime_log_tun_core_read_error, files.sanitize(error.toString())))
                }
            }, "homevpn-tun-output").apply { isDaemon = true; start() }
            val localDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
            while (!rpcReady.await(150, TimeUnit.MILLISECONDS)) {
                checkChild(child)
                if (System.nanoTime() >= localDeadline) throw IOException(app.getString(R.string.network_runtime_error_tun_local_management_not_ready))
            }
            checkChild(child)
            files.requireCommand(child, "VersionGet")
            val mac = provisionAccount(files, child)
            val securityReader = NativeConnectionSecurityReader(verified.certificatePem, config.certificateSha256)
            val account = waitForAccount(files, child)
            status(app.getString(R.string.network_runtime_status_tun_session_getting_address))
            checkChild(child)
            publishSecurity(securityReader.read(account))
            callbacks.onReady(verified.network, checkNotNull(ethernet), mac)
            monitorAccount(files, child, securityReader)
        } catch (error: Exception) {
            failure = error
        } finally {
            Thread.interrupted()
            runCatching { ethernet?.close() }
            val daemonExited = daemon?.let(::stopProcess) ?: true
            val commandsExited = workspace?.closeCommand() ?: true
            output?.let { runCatching { it.join(500) } }
            val (probe, report) = synchronized(lock) {
                val report = stopReason ?: failure.takeUnless { stopping }
                stopping = true
                owner = null
                (preflight to report).also { preflight = null }
            }
            runCatching { probe?.close() }
            if (daemonExited && commandsExited) {
                workspace?.let {
                    if (!it.directory.deleteRecursively()) record("WARN", "TUN_NATIVE", app.getString(R.string.network_runtime_log_tun_cleanup_failed))
                }
            } else {
                record("ERROR", "TUN_NATIVE", app.getString(R.string.network_runtime_log_tun_process_exit_timeout))
            }
            report?.let {
                record("ERROR", "TUN_NATIVE", workspace?.sanitize(it.stackTraceToString()) ?: it.stackTraceToString())
                callbacks.onStopped(it)
            }
        }
    }

    private fun nativeOptions(): Map<String, String> = buildMap {
        if (!config.ipv6Enabled) put("HOMEVPN_DISABLE_IPV6", "1")
        if (!config.enableUdpAcceleration) put("HOMEVPN_DISABLE_UDP_ACCELERATION", "1")
        if (config.sslVersion != "DEFAULT") put("HOMEVPN_FRAME_TLS_VERSION", config.sslVersion)
        requestedCiphers?.let { put("HOMEVPN_FRAME_TLS_CIPHERS", it.joinToString(":")) }
    }

    private fun provisionAccount(files: Workspace, child: Process): ByteArray {
        status(app.getString(R.string.network_runtime_status_tun_account_configuring))
        files.requireCommand(child, "NicCreate home")
        val nics = files.requireCommand(child, "NicList", csv = true)
        val mac = nics.output.lineSequence().mapNotNull { HOME_NIC.matchEntire(it) }.singleOrNull()
            ?.groupValues?.get(1)?.let(HEX::parseHex)
            ?: throw IOException(app.getString(R.string.network_runtime_error_tun_active_adapter_mac_missing))
        if (!mac.contentEquals(adapterMac)) throw IOException(app.getString(R.string.network_runtime_error_tun_active_adapter_mac_mismatch))
        val host = config.serverHostname.removeSurrounding("[", "]")
        val address = if (host.contains(':')) "[$host]:${config.serverPort}" else "$host:${config.serverPort}"
        files.requireCommand(child, "AccountCreate home /SERVER:${token(address)} " +
            "/HUB:${token(config.hub)} /USERNAME:${token(config.username)} /NICNAME:home")
        files.requireCommand(child, "AccountServerCertSet home /LOADCERT:${token(files.certificate.path)}")
        files.requireCommand(child, "AccountServerCertEnable home")
        record("INFO", "NATIVE_PROVISION", "mode=TUN ${config.authentication.diagnosticSummary}")
        config.authentication.provision(files.directory, ::writePrivate) { script ->
            files.requireCommand(child, script, confidential = true)
        }
        files.requireCommand(child, "AccountConnect home")
        return mac
    }

    private fun waitForAccount(files: Workspace, child: Process): Map<String, String> {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.SECONDS.toNanos(45)
        var latest = "phase=unavailable"
        while (System.nanoTime() < deadline) {
            val result = files.command(child, "AccountStatusGet home", csv = true)
            val rows = NativeCoreRunner.csvRows(result.output)
            val state = accountState(result.exitCode, rows)
            val report = "phase=$state exit=${result.exitCode}"
            if (report != latest) {
                latest = report
                record("DEBUG", "NATIVE_SESSION_STATE", "mode=TUN $report elapsed_ms=${elapsedMs(started)}")
            }
            if (state == "established") return rows
            Thread.sleep(500)
        }
        record("WARN", "NATIVE_SESSION_STATE", "mode=TUN outcome=timeout $latest elapsed_ms=${elapsedMs(started)}")
        throw IOException(app.getString(R.string.network_runtime_error_tun_account_connection_failed))
    }

    private fun monitorAccount(files: Workspace, child: Process, securityReader: NativeConnectionSecurityReader) {
        while (true) {
            Thread.sleep(2_000)
            val result = files.command(child, "AccountStatusGet home", csv = true)
            val rows = NativeCoreRunner.csvRows(result.output)
            val state = accountState(result.exitCode, rows)
            if (state != "established") {
                publishSecurity(null)
                record("WARN", "NATIVE_SESSION_STATE", "mode=TUN outcome=lost phase=$state exit=${result.exitCode}")
                throw IOException(app.getString(R.string.error_session_disconnected))
            }
            publishSecurity(securityReader.read(rows))
        }
    }

    private fun accountState(exitCode: Int, rows: Map<String, String>): String =
        if (exitCode != 0) "rpc-error" else nativeAccountPhase(rows["Session Status"])

    private fun publishSecurity(security: NativeConnectionSecurity?) {
        if (stopping || security == connectionSecurity) return
        connectionSecurity = security
        callbacks.onSecurityChanged()
    }

    private fun checkRunning() {
        if (stopping) throw InterruptedIOException(app.getString(R.string.network_runtime_error_tun_client_closed))
    }

    private fun checkChild(child: Process) {
        checkRunning()
        if (!child.isAlive) throw IOException(app.getString(R.string.network_runtime_error_tun_client_exit, child.exitValue()))
    }

    private fun status(message: String) {
        checkRunning()
        record("INFO", "TUN_NATIVE", message)
        callbacks.onStatus(message)
    }

    private fun record(level: String, tag: String, message: String) =
        DiagnosticLog.record(level, tag, message, config.sessionId)

    private inner class Workspace(val directory: File, private val port: Int, private val secret: String) {
        private val secretFile = File(directory, "management.secret")
        val certificate = File(directory, "server.pem")
        private var commandProcess: Process? = null

        fun initialize(certificatePem: ByteArray) {
            Os.chmod(directory.path, 448) // 0700
            writePrivate(secretFile, secret.toByteArray(Charsets.US_ASCII))
            writePrivate(certificate, certificatePem)
            writePrivate(File(directory, "lang.config"), "en\n".toByteArray(Charsets.US_ASCII))
            app.assets.open("native-core/hamcore.se2").use { input ->
                File(directory, "hamcore.se2").outputStream().use { output -> input.copyTo(output) }
            }
        }

        fun launch(program: String, args: List<String>, overrides: Map<String, String> = emptyMap()): Process {
            val binary = File(app.applicationInfo.nativeLibraryDir, "libhomevpn_$program.so")
            if (!binary.isFile) throw IOException(app.getString(R.string.network_runtime_error_softether_core_missing))
            val builder = ProcessBuilder(listOf(binary.path) + args)
                .directory(directory).redirectErrorStream(true)
            builder.environment().apply {
                keys.removeAll { it.startsWith("HOMEVPN_") }
                put("HOMEVPN_DATA_DIR", directory.path)
                put("HOMEVPN_ADMIN_SECRET_FILE", secretFile.path)
                put("HOMEVPN_ROOTLESS_RPC_PORT", port.toString())
                put("LANG", "C.UTF-8")
                put("LC_ALL", "C.UTF-8")
                putAll(overrides)
            }
            synchronized(lock) {
                checkRunning()
                return builder.start()
            }
        }

        fun requireCommand(child: Process, script: String, csv: Boolean = false,
                           confidential: Boolean = false): NativeCoreRunner.CommandResult {
            val name = script.substringBefore(' ')
            return traceProvisioningCommand("TUN", config.sessionId, name) {
                val result = command(child, script, csv)
                // vpncmd omits the completion banner in CSV mode.
                if (result.exitCode != 0 || !csv && !result.output.contains("The command completed successfully.")) {
                    val summary = app.getString(R.string.network_runtime_error_tun_management_operation, name, result.exitCode)
                    // vpncmd can echo transformed password arguments that ordinary redaction cannot recover.
                    val detail = if (confidential) "" else "\n${sanitize(result.output.takeLast(1800))}"
                    throw IOException(summary + detail)
                }
                result
            }
        }

        fun command(child: Process, script: String, csv: Boolean): NativeCoreRunner.CommandResult {
            checkChild(child)
            check(commandProcess == null)
            val input = Files.createTempFile(directory.toPath(), "command-", ".in").toFile()
            try {
                writePrivate(input, "$script\n".toByteArray(Charsets.UTF_8))
                val arguments = mutableListOf("127.0.0.1", "/CLIENT", "/IN:${input.path}")
                if (csv) arguments += "/CSV"
                checkChild(child)
                val statusOptions = if (csv && script == "AccountStatusGet home") mapOf("HOMEVPN_CONNECTION_DETAILS" to "1") else emptyMap()
                val process = launch("vpncmd", arguments, statusOptions).also { commandProcess = it }
                val collected = ByteArrayOutputStream()
                val reader = Thread({
                    runCatching {
                        process.inputStream.use { stream ->
                            val bytes = ByteArray(4096)
                            while (true) {
                                val count = stream.read(bytes)
                                if (count < 0) break
                                val available = MAX_COMMAND_OUTPUT - collected.size()
                                if (available > 0) collected.write(bytes, 0, minOf(available, count))
                            }
                        }
                    }
                }, "homevpn-tun-vpncmd").apply { isDaemon = true; start() }
                if (!process.waitFor(8, TimeUnit.SECONDS)) throw IOException(app.getString(R.string.network_runtime_error_tun_local_management_timeout))
                reader.join(1_000)
                if (reader.isAlive) throw IOException(app.getString(R.string.network_runtime_error_tun_local_management_output))
                checkChild(child)
                return NativeCoreRunner.CommandResult(process.exitValue(), collected.toString(Charsets.UTF_8))
            } finally {
                closeCommand()
                input.delete()
            }
        }

        fun closeCommand(): Boolean {
            val process = commandProcess ?: return true
            if (!stopProcess(process)) return false
            commandProcess = null
            return true
        }

        fun sanitize(value: String): String =
            NativeCoreRunner.sanitizeOutput(value, listOf(secret, config.authentication.password, config.username))
    }

    private companion object {
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val HEX: HexFormat = HexFormat.of().withUpperCase()
        val HOME_NIC = Regex("""\s*"?home"?\s*,\s*"?Enabled"?\s*,\s*"?([0-9a-fA-F]{12})"?\s*,.*""")
        val SUPPORTED_TLS = setOf("DEFAULT", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        val TLS_CIPHER = Regex("""TLS_[A-Z0-9_]+""")
        const val MAX_COMMAND_OUTPUT = 256 * 1024

        fun elapsedMs(started: Long): Long = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)

        fun validMac(mac: ByteArray): Boolean =
            mac.size == 6 && mac[0].toInt() and 1 == 0 && mac.any { it != 0.toByte() }

        fun writePrivate(file: File, contents: ByteArray) {
            file.writeBytes(contents)
            Os.chmod(file.path, 384) // 0600
        }

        fun stopProcess(process: Process): Boolean {
            runCatching { process.outputStream.close() }
            try {
                if (process.waitFor(2, TimeUnit.SECONDS)) return true
                process.destroy()
                if (process.waitFor(2, TimeUnit.SECONDS)) return true
                process.destroyForcibly()
                return process.waitFor(2, TimeUnit.SECONDS)
            } catch (_: InterruptedException) {
                process.destroyForcibly()
                return runCatching { process.waitFor(2, TimeUnit.SECONDS) }.getOrDefault(false)
            }
        }
    }
}
