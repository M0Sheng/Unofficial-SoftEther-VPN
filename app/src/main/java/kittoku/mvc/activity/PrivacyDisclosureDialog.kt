package kittoku.mvc.activity

import android.app.Dialog
import android.content.DialogInterface
import android.os.Bundle
import android.widget.Toast
import androidx.core.os.bundleOf
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.FragmentManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.R
import kittoku.mvc.privacy.PrivacyDisclosure

internal class PrivacyDisclosureDialog : DialogFragment() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val disclosure = PrivacyDisclosure.valueOf(requireNotNull(requireArguments().getString(DISCLOSURE_KEY)))
        return MaterialAlertDialogBuilder(requireContext())
            .setTitle(disclosure.title)
            .setMessage(disclosure.message)
            .setNegativeButton(R.string.disclosure_decline) { _, _ -> reply(false) }
            .setPositiveButton(R.string.disclosure_accept) { _, _ ->
                val accepted = disclosure.accept(requireContext())
                if (!accepted) Toast.makeText(requireContext(), R.string.disclosure_save_failed, Toast.LENGTH_LONG).show()
                reply(accepted)
            }.create()
    }

    override fun onCancel(dialog: DialogInterface) {
        reply(false)
        super.onCancel(dialog)
    }

    private fun reply(accepted: Boolean) {
        parentFragmentManager.setFragmentResult(RESULT, bundleOf(ACCEPTED to accepted))
    }

    companion object {
        const val RESULT = "privacy-disclosure-result"
        const val ACCEPTED = "accepted"
        private const val DISCLOSURE_KEY = "disclosure"

        fun show(manager: FragmentManager, disclosure: PrivacyDisclosure) {
            val tag = "privacy-disclosure-${disclosure.name}"
            if (manager.isStateSaved || manager.findFragmentByTag(tag) != null) return
            PrivacyDisclosureDialog().apply { arguments = bundleOf(DISCLOSURE_KEY to disclosure.name) }
                .show(manager, tag)
        }
    }
}
