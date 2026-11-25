package kittoku.mvc.privacy

import android.content.Context
import android.content.SharedPreferences
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.routing.AppRoutingMode
import kittoku.mvc.routing.AppRoutingSettings

internal enum class PrivacyDisclosure(
    private val acceptanceKey: String,
    val title: Int,
    val message: Int,
) {
    VPN("vpn_v1", R.string.vpn_disclosure_title, R.string.vpn_disclosure_message),
    APP_INVENTORY("app_inventory_v1", R.string.app_inventory_disclosure_title, R.string.app_inventory_disclosure_message);

    private fun consentPreferences(context: Context) =
        context.getSharedPreferences("privacy_disclosures", Context.MODE_PRIVATE)

    fun accepted(context: Context): Boolean = consentPreferences(context).getBoolean(acceptanceKey, false)

    fun accept(context: Context): Boolean {
        val prefs = consentPreferences(context)
        if (accepted(context)) return true
        if (prefs.edit().putBoolean(acceptanceKey, true).commit()) return true
        prefs.edit().remove(acceptanceKey).apply()
        return false
    }

    companion object {
        fun pendingConnection(context: Context, prefs: SharedPreferences): PrivacyDisclosure? {
            if (!VPN.accepted(context)) return VPN
            if (APP_INVENTORY.accepted(context)) return null
            // TAP may query packages while applying address-only routing or recovering an owned route journal.
            val isTap = getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) != BackendModePolicy.TUN
            val usesInventory = isTap || runCatching { AppRoutingSettings(context).load().mode != AppRoutingMode.ALL }
                .getOrDefault(true)
            return APP_INVENTORY.takeIf { usesInventory }
        }
    }
}
