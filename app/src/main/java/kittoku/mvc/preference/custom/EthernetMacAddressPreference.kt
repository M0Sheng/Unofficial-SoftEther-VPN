package kittoku.mvc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import androidx.preference.Preference
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue

internal class EthernetMacAddressPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs) {
    init {
        setTitle(R.string.pref_mac)
        isSelectable = false
    }

    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || key == MvcPreference.ETHERNET_MAC_ADDRESS.name || key == MvcPreference.BACKEND_MODE.name) {
            refreshAddress()
        }
    }

    override fun onAttached() {
        super.onAttached()
        sharedPreferences?.registerOnSharedPreferenceChangeListener(listener)
        refreshAddress()
    }

    override fun onDetached() {
        sharedPreferences?.unregisterOnSharedPreferenceChangeListener(listener)
        super.onDetached()
    }

    private fun refreshAddress() {
        val preferences = sharedPreferences ?: return
        isEnabled = getStringPrefValue(MvcPreference.BACKEND_MODE, preferences) == BackendModePolicy.TUN
        if (!isEnabled) {
            setSummary(R.string.pref_mac_native_summary)
            return
        }
        val mac = getStringPrefValue(MvcPreference.ETHERNET_MAC_ADDRESS, preferences)
        val label = if (mac.isEmpty()) context.getString(R.string.pref_no_address) else mac.chunked(2).joinToString(":")
        summary = context.getString(R.string.pref_mac_summary, label)
    }
}
