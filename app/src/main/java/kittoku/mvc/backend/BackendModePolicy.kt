package kittoku.mvc.backend

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
/** Canonical modes and the only permitted automatic retirement migration. */
internal object BackendModePolicy {
    const val ROOT_NATIVE = "ROOT_NATIVE"
    const val TUN = "TUN"
    const val RETIRED_ROOT_TAP = "ROOT_TAP"

    fun effective(stored: String?): String = when (stored) {
        null, RETIRED_ROOT_TAP -> ROOT_NATIVE
        ROOT_NATIVE, TUN -> stored
        else -> throw IllegalArgumentException(appText(R.string.profile_runtime_backend_select))
    }

    fun needsMigration(stored: String?): Boolean = stored == null || stored == RETIRED_ROOT_TAP

    fun migrate(stored: String?, clearPending: () -> Boolean, persistNative: () -> Boolean): String {
        val mode = effective(stored)
        if (needsMigration(stored)) {
            // Ephemeral approval belongs to its old backend; never retag it as native trust.
            check(clearPending()) { appText(R.string.profile_runtime_backend_clear_pending) }
            check(persistNative()) { appText(R.string.profile_runtime_backend_save_tap) }
        }
        return mode
    }

    fun passwordEncoding(mode: String, tunPreference: String?): String = when (mode) {
        ROOT_NATIVE -> "UTF-8"
        TUN -> (tunPreference ?: "UTF-8").also {
            require(it in listOf("UTF-8", "GBK")) { appText(R.string.profile_runtime_backend_encoding_invalid) }
        }
        else -> throw IllegalArgumentException(appText(R.string.profile_runtime_backend_invalid))
    }
}

/** Retains retry state when a failed synchronous commit already changed preference memory. */
internal class BackendMigrationState {
    private var retryNativeFlush = false

    fun migrate(stored: String?, clearPending: () -> Boolean, persistNative: () -> Boolean): String {
        val mode = BackendModePolicy.effective(stored)
        val retry = retryNativeFlush && stored == BackendModePolicy.ROOT_NATIVE
        if (!BackendModePolicy.needsMigration(stored) && !retry) {
            retryNativeFlush = false
            return mode
        }
        retryNativeFlush = true
        val result = BackendModePolicy.migrate(if (retry) BackendModePolicy.RETIRED_ROOT_TAP else stored,
            clearPending, persistNative)
        retryNativeFlush = false
        return result
    }
}
