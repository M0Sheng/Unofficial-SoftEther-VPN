package kittoku.mvc.preference

import android.annotation.SuppressLint
import android.app.Dialog
import android.content.Context
import android.graphics.Rect
import android.graphics.drawable.InsetDrawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.fragment.app.DialogFragment
import androidx.preference.EditTextPreference
import androidx.preference.EditTextPreferenceDialogFragmentCompat
import androidx.preference.ListPreference
import androidx.preference.ListPreferenceDialogFragmentCompat
import androidx.preference.MultiSelectListPreference
import androidx.preference.MultiSelectListPreferenceDialogFragmentCompat
import androidx.preference.Preference
import androidx.preference.PreferenceDialogFragmentCompat
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.PreferenceGroup
import androidx.preference.PreferenceGroupAdapter
import androidx.preference.PreferenceManager
import androidx.preference.PreferenceScreen
import androidx.preference.PreferenceViewHolder
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.shape.MaterialShapeDrawable
import kittoku.mvc.R
import kittoku.mvc.profile.ProfileStore

/** One immutable identity per inflated screen; never rebind old editors to a new activation. */
internal class ProfilePreferenceGuard(
    private val host: PreferenceFragmentCompat,
    private val profiles: ProfileStore,
) {
    private var prepared: ProfileEditorIdentity? = null
    private var bound: ProfileEditorIdentity? = null
    private var screen: PreferenceScreen? = null
    private var pendingScreen: PreferenceScreen? = null
    private var pendingEnabled = true

    fun prepareInflation() { prepared = ProfileEditorIdentity.current(host.requireContext()) }

    /** A disabled setting still accepts a tap to explain how to enable it. */
    @SuppressLint("RestrictedApi")
    fun unavailableSettingsAdapter(screen: PreferenceScreen): RecyclerView.Adapter<*>? {
        if (prepared != null) return null
        return object : PreferenceGroupAdapter(screen) {
            override fun onBindViewHolder(holder: PreferenceViewHolder, position: Int) {
                super.onBindViewHolder(holder, position)
                val preference = getItem(position)
                val unavailable = preference?.key in ProfileStore.SETTINGS_KEYS || preference?.key == "DESTINATION_ROUTING"
                val row = holder.itemView
                row.alpha = if (unavailable) 0.38f else 1f
                if (!unavailable) return
                fun disableChildren(view: View) {
                    if (view is ViewGroup) {
                        for (index in 0 until view.childCount) {
                            val child = view.getChildAt(index)
                            child.isEnabled = false
                            disableChildren(child)
                        }
                    }
                }
                disableChildren(row)
                row.isEnabled = true
                row.isFocusable = true
                row.setOnClickListener {
                    Toast.makeText(row.context, R.string.settings_no_profile, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    /** onCreateAdapter precedes onAttached in AndroidX 1.2.1. Keep the screen disabled until
     * this posted task runs after that synchronous bind, using only public lifecycle APIs. */
    fun bindAfterAdapter(next: PreferenceScreen) {
        if (pendingScreen !== next) {
            pendingScreen = next
            pendingEnabled = next.isEnabled
        }
        val enabled = pendingEnabled
        next.isEnabled = false
        host.listView.post {
            if (host.view != null && host.preferenceScreen === next) {
                bindAfterAttached()
                next.isEnabled = enabled
            }
        }
    }

    private fun bindAfterAttached() {
        val next = host.preferenceScreen ?: return
        if (screen === next) return
        screen = next
        bound = prepared
        val identity = bound
        fun visit(preference: Preference) {
            if (preference.key in ProfileStore.SETTINGS_KEYS) {
                val previous = preference.onPreferenceChangeListener
                preference.onPreferenceChangeListener = Preference.OnPreferenceChangeListener { changed, value ->
                    when {
                        identity == null || identity != ProfileEditorIdentity.current(changed.context) -> {
                            ProfileEditorIdentity.notifyChanged(changed.context)
                            false
                        }
                        value == null || previous?.onPreferenceChange(changed, value) == false -> false
                        else -> try {
                            profiles.saveSettings(identity.profileId, identity.activation, mapOf(changed.key to value))
                                .also { if (!it) ProfileEditorIdentity.notifyChanged(changed.context) }
                        } catch (_: RuntimeException) {
                            Toast.makeText(changed.context, R.string.profile_runtime_save_profiles_failed, Toast.LENGTH_LONG).show()
                            false
                        }
                    }
                }
            }
            if (preference is PreferenceGroup) for (index in 0 until preference.preferenceCount) visit(preference.getPreference(index))
        }
        visit(next)
    }

    @Suppress("DEPRECATION")
    fun showDialog(preference: Preference): Boolean {
        val key = preference.key ?: return false
        if (key !in ProfileStore.PROFILE_KEYS) return false
        val identity = bound
        if (identity == null || identity != ProfileEditorIdentity.current(host.requireContext())) {
            ProfileEditorIdentity.notifyChanged(host.requireContext())
            return true
        }
        val manager = host.parentFragmentManager
        if (manager.isStateSaved || manager.findFragmentByTag(DIALOG_TAG) != null) return true
        val dialog: PreferenceDialogFragmentCompat = when (preference) {
            is EditTextPreference -> ProfileEditTextDialog()
            is ListPreference -> ProfileListDialog()
            is MultiSelectListPreference -> ProfileMultiSelectDialog()
            else -> return false
        }
        dialog.arguments = identity.arguments(key)
        dialog.setTargetFragment(host, 0)
        dialog.show(manager, DIALOG_TAG)
        return true
    }

    /** Also closes pre-upgrade standard dialogs that have no frozen identity at all. */
    fun dismissStaleDialog() {
        val candidate = host.parentFragmentManager.findFragmentByTag(DIALOG_TAG) as? PreferenceDialogFragmentCompat ?: return
        if (candidate.arguments?.getString("key") !in ProfileStore.PROFILE_KEYS) return
        if (!ProfileEditorIdentity.isCurrent(candidate)) ProfileEditorIdentity.dismiss(candidate)
    }

    companion object { private const val DIALOG_TAG = "androidx.preference.PreferenceFragment.DIALOG" }
}

private data class ProfileEditorIdentity(val profileId: String, val activation: String) {
    fun arguments(key: String) = Bundle().apply {
        putString("key", key)
        putString(PROFILE, profileId)
        putString(ACTIVATION, activation)
    }

    companion object {
        private const val PROFILE = "profile_editor_id"
        private const val ACTIVATION = "profile_editor_activation"

        fun current(context: Context): ProfileEditorIdentity? {
            val preferences = PreferenceManager.getDefaultSharedPreferences(context)
            val id = preferences.getString(ProfileStore.ACTIVE_ID_KEY, null)?.takeIf { it.isNotBlank() } ?: return null
            val activation = preferences.getString(ProfileStore.ACTIVATION_KEY, null)?.takeIf { it.isNotBlank() } ?: return null
            return ProfileEditorIdentity(id, activation)
        }

        fun isCurrent(dialog: DialogFragment): Boolean {
            val context = dialog.context ?: return false
            val arguments = dialog.arguments ?: return false
            val id = arguments.getString(PROFILE) ?: return false
            val activation = arguments.getString(ACTIVATION) ?: return false
            return ProfileEditorIdentity(id, activation) == current(context)
        }

        fun dismiss(dialog: DialogFragment) {
            // Lifecycle callbacks can run while FragmentManager executes another transaction.
            // Hiding the dialog is immediate; enqueue its removal rather than nesting commitNow.
            dialog.dismissAllowingStateLoss()
        }

        fun notifyChanged(context: Context) {
            val message = if (current(context) == null) R.string.settings_no_profile else R.string.profile_changed
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        }
        fun notifyChanged(dialog: DialogFragment) { dialog.context?.let(::notifyChanged) }
    }
}

/** These public no-arg classes are restorable by FragmentFactory; arguments contain no credentials. */
class ProfileEditTextDialog : EditTextPreferenceDialogFragmentCompat() {
    private var restoredPassword = false

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog =
        super.onCreateDialog(savedInstanceState).applyMaterialBackground(requireContext())

    override fun onCreate(savedInstanceState: Bundle?) {
        restoredPassword = savedInstanceState != null && arguments?.getString("key") == "HOME_PASSWORD"
        if (restoredPassword) savedInstanceState?.remove(PASSWORD_TEXT_STATE)
        super.onCreate(savedInstanceState)
    }

    override fun onBindDialogView(view: View) {
        super.onBindDialogView(view)
        if (arguments?.getString("key") == "HOME_PASSWORD") view.findViewById<EditText>(android.R.id.edit)?.isSaveEnabled = false
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (arguments?.getString("key") == "HOME_PASSWORD") outState.remove(PASSWORD_TEXT_STATE)
    }

    override fun onResume() {
        super.onResume()
        if (restoredPassword || !ProfileEditorIdentity.isCurrent(this)) ProfileEditorIdentity.dismiss(this)
    }

    override fun onDialogClosed(positiveResult: Boolean) {
        if (!positiveResult || (!restoredPassword && ProfileEditorIdentity.isCurrent(this))) super.onDialogClosed(positiveResult)
        else ProfileEditorIdentity.notifyChanged(this)
    }

    private companion object { const val PASSWORD_TEXT_STATE = "EditTextPreferenceDialogFragment.text" }
}

class ProfileListDialog : ListPreferenceDialogFragmentCompat() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog =
        super.onCreateDialog(savedInstanceState).applyMaterialBackground(requireContext())

    override fun onResume() {
        super.onResume()
        if (!ProfileEditorIdentity.isCurrent(this)) ProfileEditorIdentity.dismiss(this)
    }
    override fun onDialogClosed(positiveResult: Boolean) {
        if (!positiveResult || ProfileEditorIdentity.isCurrent(this)) super.onDialogClosed(positiveResult)
        else ProfileEditorIdentity.notifyChanged(this)
    }
}

class ProfileMultiSelectDialog : MultiSelectListPreferenceDialogFragmentCompat() {
    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog =
        super.onCreateDialog(savedInstanceState).applyMaterialBackground(requireContext())

    override fun onResume() {
        super.onResume()
        if (!ProfileEditorIdentity.isCurrent(this)) ProfileEditorIdentity.dismiss(this)
    }
    override fun onDialogClosed(positiveResult: Boolean) {
        if (!positiveResult || ProfileEditorIdentity.isCurrent(this)) super.onDialogClosed(positiveResult)
        else ProfileEditorIdentity.notifyChanged(this)
    }
}

// Use the official Material container while keeping the preference dialog's
// existing window geometry, input handling, and saved state.
private fun Dialog.applyMaterialBackground(context: Context): Dialog = apply {
    val dialogWindow = window ?: return@apply
    val background = MaterialAlertDialogBuilder(context).background as? MaterialShapeDrawable ?: return@apply
    val decor = dialogWindow.decorView
    val padding = Rect()
    decor.background?.getPadding(padding)
    background.elevation = decor.elevation
    dialogWindow.setBackgroundDrawable(
        InsetDrawable(background, padding.left, padding.top, padding.right, padding.bottom)
    )
}
