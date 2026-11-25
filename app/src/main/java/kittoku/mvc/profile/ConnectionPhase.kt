package kittoku.mvc.profile

import android.content.SharedPreferences
import kittoku.mvc.i18n.appLocaleTags
import kittoku.mvc.preference.MvcPreference

/** Presentation state, separate from the request to keep the VPN running. */
internal enum class ConnectionPhase {
    DISCONNECTED, CONNECTING, CONNECTED, MANAGEMENT, CERTIFICATE_REVIEW, FAILED;

    companion object {
        const val KEY = "HOME_CONNECTION_PHASE"
        const val STATUS_LOCALES_KEY = "HOME_STATUS_LOCALES"

        fun read(prefs: SharedPreferences): ConnectionPhase {
            val stored = prefs.getString(KEY, null)
            return entries.firstOrNull { it.name == stored } ?: DISCONNECTED
        }
    }
}

internal fun SharedPreferences.Editor.putConnectionStatus(
    phase: ConnectionPhase,
    message: String,
): SharedPreferences.Editor = putString(ConnectionPhase.KEY, phase.name)
    .putString(MvcPreference.HOME_STATUS.name, message)
    .putString(ConnectionPhase.STATUS_LOCALES_KEY, appLocaleTags())

/** Avoid showing a cached status from the previous locale until the owner reports a new one. */
internal fun SharedPreferences.connectionStatus(): String {
    val locales = appLocaleTags() ?: return ""
    if (getString(ConnectionPhase.STATUS_LOCALES_KEY, null) != locales) return ""
    return getString(MvcPreference.HOME_STATUS.name, "").orEmpty()
}
