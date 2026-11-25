package kittoku.mvc.preference.accessor

import android.content.SharedPreferences
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.preference.MvcPreference

// Saved profiles store port and MTU as decimal strings. Keep that format for upgrades and imports.
private val numericDefaults = mapOf(MvcPreference.SSL_PORT to 5555, MvcPreference.ETHERNET_MTU to 1500)
private val textDefaults = mapOf(
    MvcPreference.HOME_HOSTNAME to "",
    MvcPreference.HOME_HUB to "DEFAULT",
    MvcPreference.HOME_USERNAME to "",
    MvcPreference.HOME_PASSWORD to "",
    MvcPreference.AUTH_PASSWORD_ENCODING to "UTF-8",
    MvcPreference.HOME_STATUS to "",
    MvcPreference.BACKEND_MODE to BackendModePolicy.ROOT_NATIVE,
    MvcPreference.ROUTE_MODE to "FULL",
    MvcPreference.LAN_ROUTES to "",
    MvcPreference.SSL_VERSION to "DEFAULT",
    MvcPreference.UDP_STATUS to "",
    MvcPreference.ETHERNET_MAC_ADDRESS to "",
)
private val booleanKeys = setOf(
    MvcPreference.HOME_CONNECTOR,
    MvcPreference.SSL_DO_SELECT_SUITES,
    MvcPreference.UDP_ENABLE_ACCELERATION,
)

internal fun getBooleanPrefValue(key: MvcPreference, prefs: SharedPreferences): Boolean {
    require(key in booleanKeys) { "$key is not a boolean preference" }
    return prefs.getBoolean(key.name, false)
}

internal fun getIntPrefValue(key: MvcPreference, prefs: SharedPreferences): Int {
    val fallback = numericDefaults.getValue(key)
    return prefs.getString(key.name, null)?.toIntOrNull() ?: fallback
}

internal fun getSetPrefValue(key: MvcPreference, prefs: SharedPreferences): Set<String> {
    require(key == MvcPreference.SSL_SUITES)
    return prefs.getStringSet(key.name, null).orEmpty().toSet()
}

internal fun getStringPrefValue(key: MvcPreference, prefs: SharedPreferences): String {
    val fallback = textDefaults.getValue(key)
    return prefs.getString(key.name, fallback) ?: fallback
}

internal fun setBooleanPrefValue(value: Boolean, key: MvcPreference, prefs: SharedPreferences) {
    prefs.edit().putBoolean(key.name, value).apply()
}

internal fun setIntPrefValue(value: Int, key: MvcPreference, prefs: SharedPreferences) {
    prefs.edit().putString(key.name, value.toString()).apply()
}

internal fun setSetPrefValue(value: Set<String>, key: MvcPreference, prefs: SharedPreferences) {
    prefs.edit().putStringSet(key.name, value.toSet()).apply()
}

internal fun setStringPrefValue(value: String, key: MvcPreference, prefs: SharedPreferences) {
    prefs.edit().putString(key.name, value).apply()
}
