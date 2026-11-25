package kittoku.mvc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import androidx.preference.ListPreference
import androidx.preference.Preference
import kittoku.mvc.R
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue

internal class PasswordEncodingPreference(context: Context, attrs: AttributeSet) : ListPreference(context, attrs) {
    private val backendListener = SharedPreferences.OnSharedPreferenceChangeListener { _, changed ->
        if (changed == null || changed == MvcPreference.BACKEND_MODE.name) updateAvailability()
    }

    init {
        title = context.getString(R.string.pref_password_encoding)
        dialogTitle = title
        dialogLayoutResource = R.layout.dialog_preference_details
        dialogMessage = context.getString(R.string.pref_password_encoding_description)
        entries = arrayOf(context.getString(R.string.password_encoding_utf8), context.getString(R.string.password_encoding_gbk))
        entryValues = arrayOf("UTF-8", "GBK")
        summaryProvider = SummaryProvider<Preference> { preference ->
            val prefs = preference.sharedPreferences
            if (prefs == null || getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) != "TUN") {
                context.getString(R.string.pref_password_encoding_native_summary)
            } else {
                val encoding = entry ?: context.getString(R.string.password_encoding_utf8)
                context.getString(R.string.pref_password_encoding_summary, encoding)
            }
        }
        negativeButtonText = context.getString(R.string.action_cancel)
        value = "UTF-8"
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
        isEnabled = prefs != null && getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == "TUN"
        notifyChanged()
    }
}
