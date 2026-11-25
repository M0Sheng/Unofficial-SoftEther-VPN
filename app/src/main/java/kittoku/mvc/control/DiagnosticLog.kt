package kittoku.mvc.control

import android.content.Context
import android.net.Uri
import android.os.Build
import kittoku.mvc.R
import kittoku.mvc.BuildConfig
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CopyOnWriteArraySet

/** Manual, process-local diagnostics. Never records VPN payloads or authentication packs. */
object DiagnosticLog {
    private val buffer = DiagnosticBuffer()
    private val listeners = CopyOnWriteArraySet<() -> Unit>()
    private val collectionLock = Any()
    @Volatile private var collecting = false

    fun isCollectionEnabled(): Boolean = collecting

    fun setCollectionEnabled(enabled: Boolean) {
        synchronized(collectionLock) {
            if (collecting == enabled) return
            collecting = enabled
        }
        notifyListeners()
    }

    fun startSession(backend: String, host: String, port: Int, hub: String): String {
        val id = UUID.randomUUID().toString().take(8)
        if (isCollectionEnabled()) {
            record("INFO", "SESSION", "session_start app=${BuildConfig.VERSION_NAME} code=${BuildConfig.VERSION_CODE} " +
                "android=${Build.VERSION.RELEASE} sdk=${Build.VERSION.SDK_INT} manufacturer=${Build.MANUFACTURER} " +
                "model=${Build.MODEL} backend=$backend target=$host:$port hub=$hub", id)
        }
        return id
    }

    internal fun redactCredentials(username: String, password: String) {
        buffer.registerSecret(password)
        buffer.registerSecret(username)
    }

    fun record(level: String, tag: String, message: String, sessionId: String = "") {
        if (!collecting) return
        synchronized(collectionLock) {
            if (!collecting) return
            buffer.append(DiagnosticEvent(System.currentTimeMillis(), level, tag, message, sessionId))
        }
        notifyListeners()
    }

    fun snapshot(): List<DiagnosticEvent> = buffer.snapshot()
    fun addListener(listener: () -> Unit) { listeners.add(listener) }
    fun removeListener(listener: () -> Unit) { listeners.remove(listener) }

    fun clear() {
        buffer.clear()
        notifyListeners()
    }

    /** Snapshot the capture and write it to the selected document on a background thread. */
    fun export(context: Context, uri: Uri) {
        val events = snapshot()
        val output = context.contentResolver.openOutputStream(uri, "wt")
            ?: throw IOException(context.getString(R.string.network_runtime_error_diagnostic_export_open))
        output.bufferedWriter(Charsets.UTF_8).use { writer ->
            writer.appendLine(context.getString(R.string.network_runtime_diagnostic_export_heading, BuildConfig.VERSION_NAME))
            writer.appendLine(context.getString(R.string.network_runtime_diagnostic_export_redacted))
            events.forEach { writer.appendLine(it.format()) }
        }
    }

    internal fun sanitized(value: String): String = buffer.sanitize(value)

    private fun notifyListeners() { listeners.forEach { listener -> runCatching { listener() } } }
}
