package kittoku.mvc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import androidx.preference.Preference
import androidx.preference.SwitchPreferenceCompat
import kittoku.mvc.R
import kittoku.mvc.network.IPv6Policy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationSettings

class IPv6Preference(context: Context, attrs: AttributeSet?) : SwitchPreferenceCompat(context, attrs) {
    private val tunPreference = key == IPv6Policy.TUN_PREFERENCE_KEY
    private val backendListener = SharedPreferences.OnSharedPreferenceChangeListener { _, changed ->
        if (changed == null || changed == MvcPreference.BACKEND_MODE.name ||
            changed == MvcPreference.ROUTE_MODE.name || changed == key || changed in TunDestinationSettings.KEYS) {
            updateAvailability()
        }
    }

    init {
        key = if (tunPreference) IPv6Policy.TUN_PREFERENCE_KEY else IPv6Policy.PREFERENCE_KEY
        setDefaultValue(IPv6Policy.DEFAULT_FORWARDING)
        title = context.getString(R.string.ipv6_forward_title)
        isSingleLineTitle = false
        summaryProvider = Preference.SummaryProvider<Preference> { preference ->
            val prefs = preference.sharedPreferences
            val mode = prefs?.let { getStringPrefValue(MvcPreference.BACKEND_MODE, it) }
            val enabled = prefs?.getBoolean(key, IPv6Policy.DEFAULT_FORWARDING) ?: IPv6Policy.DEFAULT_FORWARDING
            val text = when {
                tunPreference && mode == "TUN" -> tunSummary(prefs, enabled)
                !tunPreference && mode == "ROOT_NATIVE" ->
                    if (enabled) R.string.ipv6_forward_native_on else R.string.ipv6_forward_native_off
                else -> R.string.ipv6_forward_backend_unavailable
            }
            context.getString(text)
        }
    }

    private fun tunSummary(prefs: SharedPreferences?, enabled: Boolean): Int {
        val destination = try { prefs?.let { TunDestinationSettings.read(it) } }
            catch (_: RuntimeException) { return R.string.ipv6_forward_tun_invalid }
        if (destination != null) return when {
            enabled -> R.string.ipv6_forward_tun_modern_on
            destination.mode == TunDestinationMode.INCLUDE -> R.string.ipv6_forward_tun_include_off
            else -> R.string.ipv6_forward_tun_other_off
        }
        val lan = prefs?.let { getStringPrefValue(MvcPreference.ROUTE_MODE, it) == "LAN" } == true
        return when {
            enabled && lan -> R.string.ipv6_forward_tun_lan_on
            enabled -> R.string.ipv6_forward_tun_full_on
            lan -> R.string.ipv6_forward_tun_lan_off
            else -> R.string.ipv6_forward_tun_full_off
        }
    }

    override fun onAttached() {
        super.onAttached()
        sharedPreferences?.registerOnSharedPreferenceChangeListener(backendListener)
        updateAvailability()
    }

    override fun onDetached() {
        sharedPreferences?.unregisterOnSharedPreferenceChangeListener(backendListener)
        super.onDetached()
    }

    private fun updateAvailability() {
        val prefs = sharedPreferences
        val expectedBackend = if (tunPreference) "TUN" else "ROOT_NATIVE"
        isEnabled = prefs != null && getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == expectedBackend
        notifyChanged()
    }
}
