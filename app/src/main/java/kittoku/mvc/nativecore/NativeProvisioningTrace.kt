package kittoku.mvc.nativecore

import kittoku.mvc.control.DiagnosticLog
import java.util.concurrent.TimeUnit

internal class NativeSessionFailure(val code: Int, val peerClosed: Boolean = false) :
    Exception(if (peerClosed) "SoftEther peer closed the connection (error $code)" else "SoftEther session failed (error $code)")

/** Read the app-managed account's terminal result independently of log collection. */
internal fun nativeSessionFailure(line: String): NativeSessionFailure? {
    val prefix = "SoftEther managed_session_failed code="
    if (!line.startsWith(prefix)) return null
    val value = line.substring(prefix.length)
    if (value == "3 peer_closed=1") return NativeSessionFailure(3, peerClosed = true)
    return value.toIntOrNull()?.takeIf { it > 0 && it != 6 && it.toString() == value }
        ?.let { NativeSessionFailure(it) }
}

internal fun nativeAccountPhase(status: String?): String = when (status) {
    "Connection Completed (Session Established)" -> "established"
    "Connection to VPN Server Started", "Trying to Connect" -> "connecting"
    "Negotiating" -> "negotiating"
    "Authenticating User" -> "authenticating"
    "Connection is Established" -> "establishing"
    "Retrying" -> "retrying"
    "Idle" -> "idle"
    null -> "unavailable"
    else -> "other"
}

internal fun nativeOutputLevel(line: String): String =
    if (line.startsWith("SoftEther server_error ") || line.startsWith("SoftEther client_error ") ||
        line.startsWith("SoftEther session ended (error ")) "WARN" else "DEBUG"

/** Record the outcome of an app-managed command without inspecting its arguments or output. */
internal inline fun traceProvisioningCommand(
    mode: String,
    sessionId: String,
    name: String,
    command: () -> NativeCoreRunner.CommandResult,
): NativeCoreRunner.CommandResult {
    if (!DiagnosticLog.isCollectionEnabled()) return command()
    val started = System.nanoTime()
    try {
        val result = command()
        val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        DiagnosticLog.record(
            if (result.exitCode == 0) "DEBUG" else "WARN", "NATIVE_PROVISION",
            "mode=$mode command=$name exit=${result.exitCode} elapsed_ms=$elapsed", sessionId,
        )
        return result
    } catch (error: Exception) {
        val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        DiagnosticLog.record(
            "WARN", "NATIVE_PROVISION",
            "mode=$mode command=$name exception=${error.javaClass.simpleName} elapsed_ms=$elapsed", sessionId,
        )
        throw error
    }
}
