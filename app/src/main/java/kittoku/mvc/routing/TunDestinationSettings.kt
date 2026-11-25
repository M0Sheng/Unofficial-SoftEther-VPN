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

        /** UI commits must still belong to the profile and activation that opened the editor. */
        fun saveForProfile(store: ProfileStore, configuration: TunDestinationConfiguration,
                           expectedProfileId: String, expectedActivation: String): Boolean {
            if (configuration.mode != TunDestinationMode.ALL) {
                val rules = parseRootBypassRules(configuration.activeRules)
                require(configuration.mode != TunDestinationMode.INCLUDE || rules.isNotEmpty()) {
                    appText(R.string.route_error_destination_allowlist_empty)
                }
            }
            return store.saveSettings(expectedProfileId, expectedActivation, mapOf(
                MODE_KEY to configuration.mode.name,
                INCLUDE_KEY to configuration.includeRules.trim(),
                EXCLUDE_KEY to configuration.excludeRules.trim(),
            ))
        }
    }
}
