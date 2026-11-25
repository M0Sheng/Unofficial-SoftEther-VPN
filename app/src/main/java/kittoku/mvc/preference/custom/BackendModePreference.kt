package kittoku.mvc.preference.custom

import android.content.Context
import android.util.AttributeSet
import androidx.preference.ListPreference
import androidx.preference.Preference
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue

internal class BackendModePreference(context: Context, attrs: AttributeSet) : ListPreference(context, attrs) {
    init {
        title = context.getString(R.string.ui_backend)
        dialogTitle = title
        dialogLayoutResource = R.layout.dialog_preference_details
        dialogMessage = context.getString(R.string.access_method_help)
        entries = arrayOf(context.getString(R.string.backend_mode_tun), context.getString(R.string.backend_mode_native))
        entryValues = arrayOf(BackendModePolicy.TUN, BackendModePolicy.ROOT_NATIVE)
        summaryProvider = SummaryProvider<Preference> {
            val summary = when (getStringPrefValue(MvcPreference.BACKEND_MODE, it.sharedPreferences!!)) {
                BackendModePolicy.TUN -> R.string.pref_backend_mode_tun_summary
                else -> R.string.pref_backend_mode_native_summary
            }
            context.getString(summary)
        }
        negativeButtonText = context.getString(R.string.action_cancel)
        isSingleLineTitle = false
        value = BackendModePolicy.TUN
    }
}
