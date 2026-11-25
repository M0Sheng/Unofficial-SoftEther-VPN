package kittoku.mvc.nativecore

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kotlinx.coroutines.runInterruptible
import java.io.IOException
import java.util.concurrent.TimeUnit

internal object RootAccess {
    fun start(command: String, mergeError: Boolean = false): Process =
        try {
            ProcessBuilder("su", "-c", command).redirectErrorStream(mergeError).start()
        } catch (error: IOException) {
            throw IOException(appText(R.string.network_runtime_error_root_access), error)
        }

    suspend fun requireGranted() = runInterruptible { checkGranted() }

    fun checkGranted() {
        val process = start("exec /system/bin/id -u")
        try {
            if (!process.waitFor(25, TimeUnit.SECONDS)) {
                throw IOException(appText(R.string.network_runtime_error_root_authorization_timeout))
            }
            if (process.exitValue() != 0 || process.inputStream.bufferedReader().use { it.readLine()?.trim() } != "0") {
                throw IOException(appText(R.string.network_runtime_error_root_access))
            }
        } finally {
            process.destroy()
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
        }
    }
}
