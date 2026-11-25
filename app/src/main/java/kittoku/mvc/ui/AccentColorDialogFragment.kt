package kittoku.mvc.ui

import android.app.Dialog
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.style.DynamicDrawableSpan
import android.text.style.ImageSpan
import androidx.fragment.app.DialogFragment
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.R
import kotlin.math.roundToInt

internal class AccentColorDialogFragment : DialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val host = requireActivity()
        val builder = MaterialAlertDialogBuilder(host)
        val context = builder.context
        val size = (20 * context.resources.displayMetrics.density).roundToInt()
        val border = context.resources.displayMetrics.density.roundToInt()
        val outline = MaterialColors.getColor(context, com.google.android.material.R.attr.colorOutline, 0)
        val choices = AccentColor.entries.filter { it.seed != null }
        val labels = choices.map { color ->
            val swatch = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(MaterialColors.getColorRoles(context, requireNotNull(color.seed)).accent)
                setStroke(border, outline)
                setBounds(0, 0, size, size)
            }
            SpannableString("   ${context.getString(color.label)}").apply {
                setSpan(ImageSpan(swatch, DynamicDrawableSpan.ALIGN_CENTER), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
        }.toTypedArray()

        return builder.setTitle(R.string.appearance_accent_title)
            .setSingleChoiceItems(labels, choices.indexOf(AccentSettings.current(host))) { _, which ->
                val changed = AccentSettings.save(host, choices[which])
                dismiss()
                if (changed) host.recreate()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
    }

    companion object {
        const val TAG = "accent-color-dialog"
    }
}
