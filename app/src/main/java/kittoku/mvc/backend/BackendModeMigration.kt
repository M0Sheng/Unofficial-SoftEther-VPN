package kittoku.mvc.backend

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.tls.CertificateTrustStore

/** Runs for all application entrypoints, and again before a connection reads parameters. */
internal object BackendModeMigration {
    private val lock = Any()
    private val state = BackendMigrationState()

    fun migrate(context: Context, prefs: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)): String = synchronized(lock) {
        state.migrate(prefs.getString(MvcPreference.BACKEND_MODE.name, null),
            clearPending = { CertificateTrustStore(context).clearPending() },
            persistNative = { prefs.edit().putString(MvcPreference.BACKEND_MODE.name, BackendModePolicy.ROOT_NATIVE).commit() })
    }
}
