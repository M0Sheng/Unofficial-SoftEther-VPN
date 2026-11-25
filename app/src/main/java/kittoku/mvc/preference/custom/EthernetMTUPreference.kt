package kittoku.mvc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.text.InputType
import android.util.AttributeSet
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getIntPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue

internal class EthernetMTUPreference(context: Context, attrs: AttributeSet) : EditTextPreference(context, attrs) {
    init {
        setTitle(R.string.pref_mtu)
        setDialogTitle(R.string.pref_mtu)
        setPositiveButtonText(R.string.action_save)
        setNegativeButtonText(R.string.action_cancel)
        setOnBindEditTextListener { it.inputType = InputType.TYPE_CLASS_NUMBER }
        summaryProvider = SummaryProvider<Preference> { preference ->
            val mtu = getIntPrefValue(MvcPreference.ETHERNET_MTU, requireNotNull(preference.sharedPreferences))
            context.getString(R.string.pref_mtu_summary, mtu)
        }
    }

    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, changed ->
        if (changed == null || changed == MvcPreference.BACKEND_MODE.name) refreshAvailability()
    }

    override fun onAttached() {
        super.onAttached()
        sharedPreferences?.registerOnSharedPreferenceChangeListener(listener)
        refreshAvailability()
    }

    override fun onDetached() {
        sharedPreferences?.unregisterOnSharedPreferenceChangeListener(listener)
        super.onDetached()
    }

    private fun refreshAvailability() {
        isEnabled = sharedPreferences?.let { getStringPrefValue(MvcPreference.BACKEND_MODE, it) } == BackendModePolicy.TUN
    }
}
