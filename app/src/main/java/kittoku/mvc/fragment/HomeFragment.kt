package kittoku.mvc.fragment

import android.app.Dialog
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputFilter
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kittoku.mvc.R
import kittoku.mvc.activity.ProfileEditActivity
import kittoku.mvc.profile.ImportedSoftEtherProfile
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.profile.ProfileSummary
import kittoku.mvc.profile.ProfileUiState
import kittoku.mvc.profile.SoftEtherProfileFile
import kittoku.mvc.profile.UnsupportedSoftEtherProfileException
import kittoku.mvc.tls.CertificateTrustStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

/** UUID-bound profile cards. Connection values are edited only in the independent draft editor. */
internal class HomeFragment : Fragment(R.layout.fragment_profiles) {
    private val store by lazy { ProfileStore(requireContext()) }
    private val main = Handler(Looper.getMainLooper())
    private var modal: Dialog? = null
    private var listAdapter: ProfilesAdapter? = null
    private var exportId: String? = null
    private val importDocument = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) readImport(uri)
    }
    private val exportDocument = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val id = exportId
        exportId = null
        if (uri != null && id != null) writeExport(id, uri)
    }
    private val refresh = Runnable { render() }
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || key in ProfileStore.PROFILE_KEYS || key in setOf(ProfileStore.REGISTRY_KEY,
                ProfileStore.ACTIVE_ID_KEY, ProfileStore.ACTIVATION_KEY, "HOME_CONNECTOR")) {
            main.removeCallbacks(refresh)
            main.post(refresh)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        exportId = savedInstanceState?.getString(EXPORT_ID)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(EXPORT_ID, exportId)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        listAdapter = ProfilesAdapter(::selectProfile, ::showMenu)
        view.findViewById<RecyclerView>(R.id.profilesList).apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = listAdapter
        }
        view.findViewById<MaterialButton>(R.id.profilesImport).setOnClickListener {
            // Desktop .vpn files can be reported as text, binary or an unknown MIME type.
            runCatching { importDocument.launch(arrayOf("*/*")) }.onFailure { toast(R.string.profile_import_file_failed) }
        }
        view.findViewById<MaterialButton>(R.id.profilesNew).setOnClickListener { showNameDialog(NameAction.CREATE, null) }
        render()
    }

    override fun onStart() {
        super.onStart()
        store.preferences.registerOnSharedPreferenceChangeListener(listener)
        render()
    }
    override fun onStop() {
        store.preferences.unregisterOnSharedPreferenceChangeListener(listener)
        main.removeCallbacks(refresh)
        super.onStop()
    }
    override fun onDestroyView() {
        modal?.dismiss()
        modal = null
        view?.findViewById<RecyclerView>(R.id.profilesList)?.adapter = null
        listAdapter = null
        main.removeCallbacks(refresh)
        super.onDestroyView()
    }

    private fun state(): ProfileUiState? = runCatching { store.state() }.getOrNull()
    private fun busy() = store.preferences.getBoolean("HOME_CONNECTOR", false)

    private fun render() {
        val root = view ?: return
        val state = state()
        root.findViewById<MaterialButton>(R.id.profilesNew).isEnabled = state != null
        root.findViewById<MaterialButton>(R.id.profilesImport).isEnabled = state != null
        root.findViewById<TextView>(R.id.profilesCount).text = if (state == null) getString(R.string.profile_read_failed)
            else getString(R.string.profiles_count, state.profiles.size)
        root.findViewById<TextView>(R.id.profilesNotice).setText(when {
            state?.profiles?.isEmpty() == true -> R.string.profiles_empty_hint
            busy() -> R.string.profiles_list_running
            else -> R.string.profiles_list_hint
        })
        listAdapter?.submit(state)
    }

    private fun selectProfile(profile: ProfileSummary) {
        val before = state() ?: return toast(R.string.profile_read_failed)
        if (before.activeId == profile.id) return
        if (busy()) return toast(R.string.profiles_select_stop)
        val activation = store.preferences.getString(ProfileStore.ACTIVATION_KEY, null)
        fun proceed(save: Boolean) {
            if (store.preferences.getString(ProfileStore.ACTIVE_ID_KEY, null) != before.activeId ||
                store.preferences.getString(ProfileStore.ACTIVATION_KEY, null) != activation) {
                toast(R.string.profile_changed)
                return
            }
            mutate { store.select(profile.id, save) }
        }
        if (!before.hasUnsavedChanges) { proceed(false); return }
        show(MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profile_unsaved_title)
            .setMessage(R.string.profile_unsaved_message)
            .setPositiveButton(R.string.profile_save_continue) { _, _ -> proceed(true) }
            .setNegativeButton(R.string.profile_discard_continue) { _, _ -> proceed(false) }
            .setNeutralButton(R.string.action_cancel, null).create())
    }

    private fun showMenu(profile: ProfileSummary) {
        val sheet = BottomSheetDialog(requireContext())
        val padding = resources.getDimensionPixelSize(R.dimen.ui_page_inset)
        val content = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
        }
        content.addView(TextView(requireContext()).apply {
            text = profile.name
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleLarge)
            setTextColor(ContextCompat.getColor(context, R.color.ui_text_primary))
        })
        content.addView(TextView(requireContext()).apply {
            text = profile.serverLabel
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(ContextCompat.getColor(context, R.color.ui_text_secondary))
            setPadding(0, dp(6), 0, dp(12))
        })
        val actions = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
        }
        content.addView(actions)
        fun action(title: Int, operation: () -> Unit) {
            val button = layoutInflater.inflate(R.layout.item_profile_action, actions, false) as MaterialButton
            button.setText(title)
            button.setOnClickListener { sheet.dismiss(); operation() }
            actions.addView(button)
        }
        action(R.string.profiles_edit) { openEditor(profile.id) }
        action(R.string.profile_rename) { showNameDialog(NameAction.RENAME, profile) }
        action(R.string.profile_copy) { showNameDialog(NameAction.COPY, profile) }
        action(R.string.profile_export_file) { chooseExportLocation(profile) }
        action(R.string.profile_delete) { confirmDelete(profile) }
        sheet.setContentView(NestedScrollView(requireContext()).apply { addView(content) })
        show(sheet)
    }

    private enum class NameAction { CREATE, RENAME, COPY }

    private fun readImport(uri: Uri) {
        val app = requireContext().applicationContext
        val defaultProfileName = getString(R.string.profile_runtime_imported_name)
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    requireNotNull(app.contentResolver.openInputStream(uri)).use { input ->
                        SoftEtherProfileFile.read(input, defaultProfileName)
                    }
                }
            }
            if (!isAdded || view == null) return@launch
            result.onSuccess(::confirmImport).onFailure {
                toast(if (it is UnsupportedSoftEtherProfileException) R.string.profile_import_unsupported else R.string.profile_import_file_failed)
            }
        }
    }

    private fun confirmImport(profile: ImportedSoftEtherProfile) {
        val host = profile.values.getValue("HOME_HOSTNAME") as String
        val port = profile.values.getValue("SSL_PORT") as String
        val endpoint = if (':' in host && !host.startsWith('[')) "[$host]:$port" else "$host:$port"
        val summary = getString(R.string.profile_import_summary, profile.name, endpoint)
        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.profile_import_file)
            .setNegativeButton(R.string.action_cancel, null)
        if (profile.certificatePin.isEmpty()) {
            dialog.setMessage(summary)
                .setPositiveButton(R.string.profile_import_file) { _, _ -> saveImport(profile, false) }
        } else {
            dialog.setMessage("$summary\n\n" + getString(R.string.profile_import_certificate, profile.certificatePin))
                .setPositiveButton(R.string.profile_import_trust) { _, _ -> saveImport(profile, true) }
                .setNeutralButton(R.string.profile_import_skip_certificate) { _, _ -> saveImport(profile, false) }
        }
        show(dialog.create())
    }

    private fun saveImport(profile: ImportedSoftEtherProfile, trustCertificate: Boolean) {
        val app = requireContext().applicationContext
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { ProfileStore(app).importSaved(profile, trustCertificate) }
            }
            if (!isAdded || view == null) return@launch
            result.onSuccess { id ->
                render()
                openEditor(id)
            }.onFailure { toast(R.string.profile_import_save_failed) }
        }
    }

    private fun chooseExportLocation(profile: ProfileSummary) {
        if (exportId != null) return
        val filename = profile.name.map { if (it in "\\/:*?\"<>|" || it.isISOControl()) '_' else it }
            .joinToString("").trim().trim('.').ifBlank { "SoftEther" }
        exportId = profile.id
        runCatching { exportDocument.launch("$filename.vpn") }.onFailure {
            exportId = null
            toast(R.string.profile_export_file_failed)
        }
    }

    private fun writeExport(id: String, uri: Uri) {
        val app = requireContext().applicationContext
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val (profile, pin, der) = synchronized(ProfileStore.LOCK) {
                        val profile = ProfileStore(app).readForEdit(id)
                        val host = (profile.values["HOME_HOSTNAME"] as? String).orEmpty()
                        val port = (profile.values["SSL_PORT"] as? String ?: "5555").toInt()
                        val certificates = CertificateTrustStore(app)
                        Triple(profile, certificates.savedPin(id, host, port), certificates.savedCertificateDer(id, host, port))
                    }
                    val document = ByteArrayOutputStream()
                    SoftEtherProfileFile.write(document, profile, pin, der)
                    requireNotNull(app.contentResolver.openOutputStream(uri, "wt")).use(document::writeTo)
                }
            }
            toast(if (result.isSuccess) R.string.profile_export_file_done else R.string.profile_export_file_failed)
        }
    }

    private fun showNameDialog(action: NameAction, target: ProfileSummary?) {
        val dialogBuilder = MaterialAlertDialogBuilder(requireContext())
        val input = TextInputEditText(dialogBuilder.context).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            setSingleLine(true)
            filters = arrayOf(InputFilter.LengthFilter(64))
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            setText(when (action) {
                NameAction.CREATE -> ""
                NameAction.RENAME -> target?.name.orEmpty()
                NameAction.COPY -> getString(R.string.profile_copy_name, target?.name.orEmpty()).take(64)
            })
            setSelection(text?.length ?: 0)
        }
        val inputLayout = TextInputLayout(dialogBuilder.context).apply {
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
            hint = getString(R.string.profile_name)
            addView(input, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        val container = FrameLayout(dialogBuilder.context).apply {
            setPadding(dp(20), 0, dp(20), 0)
            addView(inputLayout, FrameLayout.LayoutParams(-1, -2))
        }
        val nameDialog = dialogBuilder
            .setTitle(when (action) {
                NameAction.CREATE -> R.string.profile_new
                NameAction.RENAME -> R.string.profile_rename
                NameAction.COPY -> R.string.profile_copy
            })
            .setView(container).setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_save, null).create()
        nameDialog.setOnShowListener {
            nameDialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val name = input.text?.toString().orEmpty().trim()
                if (name.isBlank() || name.length > 64 || name.any(Char::isISOControl)) {
                    inputLayout.error = getString(R.string.profile_name_invalid)
                    return@setOnClickListener
                }
                nameDialog.dismiss()
                mutate {
                    when (action) {
                        NameAction.CREATE -> openEditor(store.createSaved(name))
                        NameAction.RENAME -> store.rename(requireNotNull(target).id, name)
                        NameAction.COPY -> openEditor(store.copy(requireNotNull(target).id, name))
                    }
                }
            }
        }
        show(nameDialog)
    }

    private fun confirmDelete(target: ProfileSummary) {
        val current = state() ?: return toast(R.string.profile_read_failed)
        if (current.activeId == target.id && busy()) return toast(R.string.profiles_delete_stop)
        show(MaterialAlertDialogBuilder(requireContext()).setTitle(R.string.profile_delete)
            .setMessage(getString(R.string.profiles_delete_target, target.name))
            .setPositiveButton(R.string.profile_delete) { _, _ -> mutate { store.delete(target.id) } }
            .setNegativeButton(R.string.action_cancel, null).create())
    }

    private fun openEditor(id: String) {
        startActivity(Intent(requireContext(), ProfileEditActivity::class.java).putExtra(ProfileEditActivity.EXTRA_PROFILE_ID, id))
    }

    private fun mutate(operation: () -> Unit) {
        runCatching(operation).onFailure { toast(R.string.profile_operation_failed) }
        render()
    }

    private fun show(next: Dialog) {
        modal?.dismiss()
        modal = next
        next.setOnDismissListener { if (modal === next) modal = null }
        next.show()
    }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun toast(message: Int) { context?.let { Toast.makeText(it, message, Toast.LENGTH_LONG).show() } }

    private companion object {
        const val EXPORT_ID = "profile_export_id"
    }

    private class ProfilesAdapter(
        private val select: (ProfileSummary) -> Unit,
        private val menu: (ProfileSummary) -> Unit,
    ) : RecyclerView.Adapter<ProfilesAdapter.Holder>() {
        private var state: ProfileUiState? = null
        fun submit(value: ProfileUiState?) { state = value; notifyDataSetChanged() }
        override fun getItemCount() = state?.profiles?.size ?: 0
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = Holder(
            LayoutInflater.from(parent.context).inflate(R.layout.item_saved_profile, parent, false))
        override fun onBindViewHolder(holder: Holder, position: Int) {
            val snapshot = requireNotNull(state)
            val profile = snapshot.profiles[position]
            val active = profile.id == snapshot.activeId
            val context = holder.itemView.context
            holder.name.text = profile.name
            holder.endpoint.text = profile.serverLabel
            holder.radio.isChecked = active
            holder.marker.visibility = if (active) View.VISIBLE else View.GONE
            holder.marker.setText(if (active && snapshot.hasUnsavedChanges) R.string.profiles_selected_dirty else R.string.profiles_selected)
            holder.card.isChecked = active
            holder.card.contentDescription = listOf(profile.name, profile.serverLabel)
                .filter { it.isNotBlank() }.joinToString(", ")
            holder.card.stateDescription = if (active && snapshot.hasUnsavedChanges)
                context.getString(R.string.profiles_selected_dirty) else null
            holder.card.setOnClickListener { select(profile) }
            holder.overflow.contentDescription = context.getString(R.string.profiles_menu_for, profile.name)
            holder.overflow.setOnClickListener { menu(profile) }
        }
        class Holder(root: View) : RecyclerView.ViewHolder(root) {
            val card: MaterialCardView = root.findViewById(R.id.profileCard)
            val name: TextView = root.findViewById(R.id.profileName)
            val endpoint: TextView = root.findViewById(R.id.profileEndpoint)
            val marker: TextView = root.findViewById(R.id.profileMarker)
            val radio: RadioButton = root.findViewById(R.id.profileSelected)
            val overflow: MaterialButton = root.findViewById(R.id.profileOverflow)
        }
    }
}
