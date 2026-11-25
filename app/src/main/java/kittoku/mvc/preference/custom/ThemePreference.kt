package kittoku.mvc.preference.custom

import android.app.Dialog
import android.content.Context
import android.os.Bundle
import android.util.AttributeSet
import androidx.fragment.app.DialogFragment
import androidx.preference.Preference
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.R
import kittoku.mvc.ui.AccentSettings
import kittoku.mvc.ui.ThemeSettings

private val themeModes = listOf(ThemeSettings.SYSTEM, ThemeSettings.LIGHT, ThemeSettings.DARK)

/** Theme persistence is owned by ThemeSettings. */
class ThemePreference(context: Context, attrs: AttributeSet?) : Preference(context, attrs) {
    init {
        key = ThemeSettings.PREFERENCE_KEY
        title = context.getString(R.string.theme_settings_title)
        isPersistent = false
        isIconSpaceReserved = false
        summaryProvider = SummaryProvider<Preference> {
            val labels = context.resources.getStringArray(R.array.appearance_theme_entries)
            val selected = themeModes.indexOf(ThemeSettings.current(context))
            val accent = context.getString(AccentSettings.current(context).label)
            context.getString(R.string.theme_settings_summary, labels[selected], accent)
        }
    }

    fun refresh() = notifyChanged()
}

internal class ThemeDialogFragment : DialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val host = requireActivity()
        val labels = host.resources.getStringArray(R.array.appearance_theme_entries)
        val selected = themeModes.indexOf(ThemeSettings.current(host))
        return MaterialAlertDialogBuilder(host)
            .setTitle(R.string.appearance_theme_title)
            .setSingleChoiceItems(labels, selected) { _, which ->
                dismiss()
                if (which != selected) ThemeSettings.saveAndApply(host, themeModes[which])
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
    }

    companion object {
        const val TAG = "appearance-theme-dialog"
    }
}
