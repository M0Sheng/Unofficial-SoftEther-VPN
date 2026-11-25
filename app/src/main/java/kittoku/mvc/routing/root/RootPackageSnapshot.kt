package kittoku.mvc.routing.root

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.content.Context
import android.os.Looper
import android.os.Process
import kittoku.mvc.nativecore.RootAccess
import kittoku.mvc.routing.RootRoutingHelper
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal data class RootPackageEntry(val packageName: String, val uid: Int, val systemApp: Boolean)

/** Frame parser shared by connection bootstrap and the read-only application editor query. */
internal class RootPackageSnapshotParser(private val userId: Int) {
    private var started = false
    var complete = false
        private set
    private val entries = linkedMapOf<String, RootPackageEntry>()

    fun consume(line: String): Boolean {
        if (!line.startsWith("PACKAGE_MAP")) return false
        if (complete) throw IOException(appText(R.string.route_error_root_packages_extra))
        val fields = line.split('\t')
        when (fields.firstOrNull()) {
            "PACKAGE_MAP_BEGIN" -> {
                require(!started && fields.size == 2 && fields[1].toIntOrNull() == userId) { appText(R.string.route_error_root_packages_start) }
                started = true
            }
            "PACKAGE_MAP" -> {
                require(started && fields.size == 4 && entries.size < 12000) { appText(R.string.route_error_root_packages_format) }
                val name = fields[1]
                val uid = fields[2].toIntOrNull() ?: throw IOException(appText(R.string.route_error_root_packages_uid))
                require(name.matches(Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*")) && uid >= 0 && uid / 100000 == userId) { appText(R.string.route_error_root_packages_user) }
                require(fields[3] == "0" || fields[3] == "1") { appText(R.string.route_error_root_packages_system_flag) }
                require(!entries.containsKey(name)) { appText(R.string.route_error_root_packages_duplicate) }
                entries[name] = RootPackageEntry(name, uid, fields[3] == "1")
            }
            "PACKAGE_MAP_END" -> {
                require(started && fields.size == 3 && fields[1].toIntOrNull() == userId && fields[2].toIntOrNull() == entries.size) { appText(R.string.route_error_root_packages_missing) }
                complete = true
            }
            else -> throw IOException(appText(R.string.route_error_root_packages_unknown))
        }
        return true
    }

    fun snapshot(): List<RootPackageEntry> {
        check(complete) { appText(R.string.route_error_root_packages_incomplete) }
        return entries.values.toList()
    }
}

internal object RootPackageSnapshot {
    /** Read-only root query; does not take the routing lock, read its journal, or change policies. */
    fun load(context: Context, timeoutMs: Long = 20000): List<RootPackageEntry> {
        check(Looper.myLooper() != Looper.getMainLooper()) { appText(R.string.route_error_root_packages_background) }
        require(timeoutMs in 1000..60000) { appText(R.string.route_error_root_packages_timeout_invalid) }
        val userId = Process.myUid() / 100000
        val parser = RootPackageSnapshotParser(userId)
        val classPath = context.applicationInfo.sourceDir + ":/system/framework/services.jar"
        val command = "exec env CLASSPATH=${quote(classPath)} /system/bin/app_process /system/bin ${RootRoutingHelper::class.java.name} --packages $userId"
        RootAccess.checkGranted()
        val child = RootAccess.start(command)
        val failure = AtomicReference<Throwable?>()
        val errorText = StringBuilder()
        val reader = Thread({
            try {
                child.inputStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.forEach { line ->
                        if (line.length > 4096 || !parser.consume(line)) throw IOException(appText(R.string.route_error_root_packages_output))
                    }
                }
            } catch (error: Throwable) { failure.set(error) }
        }, "root-package-snapshot").also { it.isDaemon = true; it.start() }
        val errors = Thread({
            runCatching { child.errorStream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.forEach { line -> synchronized(errorText) { if (errorText.length < 2048) errorText.append(line.take(512)).append('\n') } }
            } }
        }, "root-package-snapshot-error").also { it.isDaemon = true; it.start() }
        try {
            if (!child.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) throw IOException(appText(R.string.route_error_root_packages_timeout))
            reader.join(1000); errors.join(500)
            failure.get()?.let { throw IOException(appText(R.string.route_error_root_packages_loading), it) }
            if (reader.isAlive || child.exitValue() != 0) throw IOException(appText(R.string.route_error_root_packages_exit, child.exitValue()) + synchronized(errorText) { errorText.toString() })
            return parser.snapshot()
        } finally {
            // Read-only helper watches EOF independently and can exit even if package IPC hangs.
            runCatching { child.outputStream.close() }
        }
    }
    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
