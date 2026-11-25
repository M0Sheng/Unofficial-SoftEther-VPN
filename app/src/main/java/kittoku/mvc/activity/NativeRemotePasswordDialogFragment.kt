package kittoku.mvc.activity

import android.app.Dialog
import android.content.DialogInterface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.nativecore.NativeRemoteManagementPassword
import kittoku.mvc.nativecore.NativeRemoteManagementSettings

/** Password fields are always created empty and excluded from hierarchy/saved state. */
class NativeRemotePasswordDialogFragment : DialogFragment() {
    private var passwordInput: EditText? = null
    private var confirmationInput: EditText? = null
    private var saveCompleted = false
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        // A rotation while the previous instance was saving must not restore a
        // non-cancelable dialog with newly empty password fields.
        isCancelable = true
        val builder = MaterialAlertDialogBuilder(requireContext())
        val context = builder.context
        val padding = (24 * resources.displayMetrics.density).toInt()
        val content = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding / 2, padding, 0)
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        content.addView(TextView(context).apply { setText(R.string.native_remote_password_rules) })
        fun passwordField(action: Int): EditText = TextInputEditText(context).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = action or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            isSingleLine = true
            // One over the maximum lets validation reject a long paste without silently accepting a truncated password.
            filters = arrayOf(InputFilter.LengthFilter(129))
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            setText("")
        }
        val password = passwordField(EditorInfo.IME_ACTION_NEXT)
        val confirmation = passwordField(EditorInfo.IME_ACTION_DONE)
        passwordInput = password
        confirmationInput = confirmation
        fun addField(input: EditText, label: Int) = TextInputLayout(
            context, null, com.google.android.material.R.attr.textInputOutlinedStyle,
        ).apply {
            hint = getString(label)
            addView(input, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            content.addView(this, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = padding / 2 })
        }
        val passwordBox = addField(password, R.string.native_remote_new_password)
        val confirmationBox = addField(confirmation, R.string.native_remote_confirm_password)
        val dialog = builder
            .setTitle(R.string.native_remote_password_title)
            .setView(content)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.native_remote_password_save, null)
            .create()
        dialog.setOnShowListener {
            dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val first = CharArray(password.text.length) { password.text[it] }
                val second = CharArray(confirmation.text.length) { confirmation.text[it] }
                if (!NativeRemoteManagementPassword.isValid(first)) {
                    first.fill('\u0000'); second.fill('\u0000')
                    passwordBox.error = getString(R.string.native_remote_password_rules)
                    return@setOnClickListener
                }
                if (!first.contentEquals(second)) {
                    first.fill('\u0000'); second.fill('\u0000')
                    confirmationBox.error = getString(R.string.native_remote_password_mismatch)
                    return@setOnClickListener
                }
                second.fill('\u0000')
                password.text.clear(); confirmation.text.clear()
                password.isEnabled = false; confirmation.isEnabled = false
                dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).isEnabled = false
                dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_NEGATIVE).isEnabled = false
                isCancelable = false
                val appContext = context.applicationContext
                val savedMessage = getString(R.string.native_remote_password_saved)
                val failedMessage = getString(R.string.native_remote_password_failed)
                Thread({
                    val result = try { runCatching { NativeRemoteManagementSettings(appContext).setPassword(first) } }
                    finally { first.fill('\u0000') }
                    result.exceptionOrNull()?.let { error ->
                        DiagnosticLog.record("ERROR", "REMOTE_MANAGEMENT", appContext.getString(R.string.profile_runtime_save_password_hash_failed, error.stackTraceToString()))
                    }
                    Handler(Looper.getMainLooper()).post {
                        Toast.makeText(appContext, if (result.isSuccess) savedMessage else failedMessage, Toast.LENGTH_LONG).show()
                        saveCompleted = true
                        isCancelable = true
                        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_NEGATIVE).isEnabled = true
                        dismissCompletedSave()
                    }
                }, "homevpn-remote-password").start()
            }
        }
        return dialog
    }

    override fun onResume() {
        super.onResume()
        dismissCompletedSave()
    }

    private fun dismissCompletedSave() {
        if (saveCompleted && isAdded && !parentFragmentManager.isStateSaved) dismiss()
    }

    override fun onDismiss(dialog: DialogInterface) {
        passwordInput?.text?.clear()
        confirmationInput?.text?.clear()
        super.onDismiss(dialog)
    }

    override fun onDestroyView() {
        passwordInput?.text?.clear()
        confirmationInput?.text?.clear()
        passwordInput = null
        confirmationInput = null
        super.onDestroyView()
    }

    companion object { const val TAG = "native_remote_management_password" }
}
