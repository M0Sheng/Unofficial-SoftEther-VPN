package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.content.Context
import android.content.SharedPreferences
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.ProfileStore

internal enum class TunDestinationMode { EXCLUDE, INCLUDE, ALL }

internal data class TunDestinationConfiguration(
    val mode: TunDestinationMode,
    val includeRules: String,
    val excludeRules: String,
) {
    val activeRules: String get() = when (mode) {
        TunDestinationMode.INCLUDE -> includeRules
        TunDestinationMode.EXCLUDE -> excludeRules
        TunDestinationMode.ALL -> ""
    }
}

/** Shared address policy for TAP and TUN, with compatibility for explicit older rules. */
internal class TunDestinationSettings private constructor() {
    companion object {
        const val MODE_KEY = "TUN_DESTINATION_MODE"
        const val INCLUDE_KEY = "TUN_DESTINATION_INCLUDE"
        const val EXCLUDE_KEY = "TUN_DESTINATION_EXCLUDE"
        val KEYS: Set<String> = setOf(MODE_KEY, INCLUDE_KEY, EXCLUDE_KEY)

        fun read(prefs: SharedPreferences): TunDestinationConfiguration? = synchronized(ProfileStore.LOCK) {
            if (!prefs.contains(MODE_KEY)) return@synchronized null
            val mode = TunDestinationMode.entries.firstOrNull { it.name == prefs.getString(MODE_KEY, null) }
                ?: throw IllegalArgumentException(appText(R.string.route_error_destination_mode))
            TunDestinationConfiguration(mode, prefs.getString(INCLUDE_KEY, "").orEmpty(),
                prefs.getString(EXCLUDE_KEY, "").orEmpty())
        }

        fun effective(context: Context, prefs: SharedPreferences, tap: Boolean): TunDestinationConfiguration? =
            synchronized(ProfileStore.LOCK) {
                read(prefs)?.let { return@synchronized it }
                if (tap) return@synchronized RootBypassSettings(context).loadLegacyConfiguration()

                val legacyExcludeRules = RoutingBypassSettings(context).rawText()
                if (legacyExcludeRules.isNotBlank() || getStringPrefValue(MvcPreference.ROUTE_MODE, prefs) != "FULL") {
                    return@synchronized null
                }
                draft(prefs, legacyExcludeRules)
            }

        /** Seed editor drafts without opting a legacy profile into a new policy. */
        fun draft(prefs: SharedPreferences, legacyExcludeRules: String): TunDestinationConfiguration =
            synchronized(ProfileStore.LOCK) {
                read(prefs) ?: TunDestinationConfiguration(TunDestinationMode.ALL,
                    prefs.getString(INCLUDE_KEY, prefs.getString("LAN_ROUTES", "")).orEmpty(),
                    prefs.getString(EXCLUDE_KEY, legacyExcludeRules).orEmpty())
            }

        fun save(prefs: SharedPreferences, configuration: TunDestinationConfiguration): Boolean =
            synchronized(ProfileStore.LOCK) { saveLocked(prefs, configuration) }

        /** UI commits must still belong to the profile and activation that opened the editor. */
        fun saveForProfile(prefs: SharedPreferences, configuration: TunDestinationConfiguration,
                           expectedProfileId: String, expectedActivation: String): Boolean =
            synchronized(ProfileStore.LOCK) {
                if (expectedProfileId.isBlank() || expectedActivation.isBlank() ||
                    prefs.getString(ProfileStore.ACTIVE_ID_KEY, null) != expectedProfileId ||
                    prefs.getString(ProfileStore.ACTIVATION_KEY, null) != expectedActivation) return@synchronized false
                saveLocked(prefs, configuration)
            }

        private fun saveLocked(prefs: SharedPreferences, configuration: TunDestinationConfiguration): Boolean {
            if (configuration.mode != TunDestinationMode.ALL) {
                val rules = parseRootBypassRules(configuration.activeRules)
                require(configuration.mode != TunDestinationMode.INCLUDE || rules.isNotEmpty()) {
                    appText(R.string.route_error_destination_allowlist_empty)
                }
            }
            val before = prefs.all.filterKeys { it in KEYS }
            val editor = prefs.edit().putString(MODE_KEY, configuration.mode.name)
                .putString(INCLUDE_KEY, configuration.includeRules.trim())
                .putString(EXCLUDE_KEY, configuration.excludeRules.trim())
            if (editor.commit()) return true

            // commit(false) may already have replaced process-local memory. Restore only
            // these three fields; unrelated settings and profile lifecycle remain untouched.
            val rollback = prefs.edit()
            KEYS.forEach(rollback::remove)
            before.forEach { (key, value) ->
                when (value) {
                    is String -> rollback.putString(key, value)
                    is Boolean -> rollback.putBoolean(key, value)
                    is Int -> rollback.putInt(key, value)
                    is Long -> rollback.putLong(key, value)
                    is Float -> rollback.putFloat(key, value)
                    is Set<*> -> rollback.putStringSet(key, value.filterIsInstance<String>().toSet())
                }
            }
            rollback.commit()
            return false
        }
    }
}
