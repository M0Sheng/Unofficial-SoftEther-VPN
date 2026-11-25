package kittoku.mvc.nativecore

import android.content.Context
import android.system.Os
import android.util.AtomicFile
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

/** App-private configuration only; changing it never starts a VPN or native process. */
class NativeRemoteManagementSettings(context: Context) {
    private val preferences = PreferenceManager.getDefaultSharedPreferences(context.applicationContext)
    private val directory = File(context.applicationContext.filesDir.canonicalFile, "official-native-core")
    // Legacy .sha1 credentials cannot be converted without the original password.
    // A separate filename makes upgrades require an explicit password reset.
    private val passwordFile = File(directory, "remote-management.sha0")

    val passwordHashFilePath: String get() = passwordFile.absolutePath
    val hasPassword: Boolean get() = synchronized(passwordLock) {
        runCatching {
            if (passwordFile.canonicalFile != passwordFile.absoluteFile || !passwordFile.isFile || passwordFile.length() != 20L) return@runCatching false
            if (Os.stat(passwordFile.absolutePath).st_mode and 511 != 384) return@runCatching false
            val stored = passwordFile.inputStream().use { it.readNBytes(21) }
            try { NativeRemoteManagementPassword.isUsableHash(stored) }
            finally { stored.fill(0) }
        }.getOrDefault(false)
    }

    var enabled: Boolean
        get() = preferences.getBoolean(ENABLED_KEY, false) && hasPassword
        set(value) {
            check(!value || hasPassword) { appText(R.string.native_remote_password_required) }
            preferences.edit().putBoolean(ENABLED_KEY, value).apply()
        }

    /** Caller owns and must clear its CharArray. Only the official 20-byte SHA-0 is persisted. */
    fun setPassword(password: CharArray) {
        val hash = NativeRemoteManagementPassword.hash(password)
        try {
            synchronized(passwordLock) {
                for (candidate in listOf(directory, passwordFile, File(passwordFile.path + ".new"), File(passwordFile.path + ".bak"))) {
                    if (candidate.canonicalFile != candidate.absoluteFile) throw IOException(appText(R.string.network_runtime_error_remote_password_symlink))
                }
                if (!directory.isDirectory && !directory.mkdirs()) throw IOException(appText(R.string.network_runtime_error_native_core_private_directory))
                Os.chmod(directory.absolutePath, 448) // 0700; shared only with this app's root-owned core.
                val atomic = AtomicFile(passwordFile)
                var stream: FileOutputStream? = null
                try {
                    stream = atomic.startWrite()
                    Os.fchmod(stream.fd, 384) // 0600 before any credential bytes are written.
                    stream.write(hash)
                    stream.fd.sync()
                    atomic.finishWrite(stream)
                    stream = null
                    Os.chmod(passwordFile.absolutePath, 384)
                    // AtomicFile can log a failed rename rather than throwing; verify the commit.
                    val stored = atomic.openRead().use { it.readNBytes(21) }
                    try {
                        if (stored.size != 20 || !MessageDigest.isEqual(stored, hash)) throw IOException(appText(R.string.native_remote_password_failed))
                    } finally { stored.fill(0) }
                } catch (error: Throwable) {
                    stream?.let { atomic.failWrite(it) }
                    throw error
                }
                val previous = preferences.getLong(PASSWORD_CHANGED_AT_KEY, 0L)
                val now = System.currentTimeMillis()
                val changedAt = if (previous < now || previous == Long.MAX_VALUE) now else previous + 1L
                preferences.edit().putLong(PASSWORD_CHANGED_AT_KEY, changedAt).apply()
            }
        } finally { hash.fill(0) }
    }

    companion object {
        const val ENABLED_KEY = "NATIVE_REMOTE_MANAGEMENT"
        const val PASSWORD_CHANGED_AT_KEY = "NATIVE_REMOTE_PASSWORD_CHANGED_AT"
        const val MANAGEMENT_PORT = 9930
        private val passwordLock = Any()
    }
}
