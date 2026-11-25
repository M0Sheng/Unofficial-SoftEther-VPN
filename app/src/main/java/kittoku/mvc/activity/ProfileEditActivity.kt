package kittoku.mvc.activity

import android.content.SharedPreferences
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.content.res.AppCompatResources
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.R
import kittoku.mvc.databinding.ActivityProfileEditBinding
import kittoku.mvc.nativecore.NativeAuthMode
import kittoku.mvc.nativecore.TapTlsPreflight
import kittoku.mvc.profile.HubCertificateApproval
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.profile.ProfileCertificateSnapshot
import kittoku.mvc.profile.ProfileCertificateStore
import kittoku.mvc.tls.CertificateEndpoint
import kittoku.mvc.tls.CertificateReviewException
import kittoku.mvc.tls.ClientCertificateFiles
import kittoku.mvc.tls.ClientKeyProtection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.util.Base64
import java.util.Locale

/** A non-exported editor for one fixed UUID. Draft credentials never leave the ViewModel. */
class ProfileEditActivity : AppCompatActivity() {
    private val store by lazy { ProfileStore(this) }
    private val certificates by lazy { ProfileCertificateStore(this) }
    private val main = Handler(Looper.getMainLooper())
    private lateinit var model: ProfileEditorViewModel
    private lateinit var binding: ActivityProfileEditBinding
    private var leaveDialog: AlertDialog? = null
    private var portDialog: AlertDialog? = null
    private var authDialog: AlertDialog? = null
    private var credentialImport: Job? = null
    private var certificateDialog: AlertDialog? = null
    private var certificateDialogSnapshot: ProfileCertificateSnapshot? = null
    private var certificateSnapshot: ProfileCertificateSnapshot? = null
    private var certificateReadFailed = true
    private var certificateEditorStale = true
    private var missing = false
    private data class HubTarget(val endpoint: CertificateEndpoint, val pin: String)

    private var hubTarget: HubTarget? = null
    private var hubJob: Job? = null
    private var hubProbe: TapTlsPreflight? = null
    private var hubDialog: AlertDialog? = null
    private var hubNames = emptyList<String>()
    private var hubCertificate: CertificateReviewException? = null
    private val selectClientCertificate = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) loadClientCredential(uri, privateKey = false)
    }
    private val selectClientKey = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) loadClientCredential(uri, privateKey = true)
    }
    private val refresh = Runnable { updateAvailability() }
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
        main.removeCallbacks(refresh)
        main.post(refresh)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        model = ViewModelProvider(this)[ProfileEditorViewModel::class.java]
        val id = intent.getStringExtra(EXTRA_PROFILE_ID)
        if (id.isNullOrBlank()) { failOpen(); return }
        if (!model.initialized) {
            val snapshot = runCatching { store.readForEdit(id) }.getOrElse { failOpen(); return }
            model.initialize(snapshot)
            if (savedInstanceState != null) toast(R.string.profiles_editor_reloaded)
        } else if (model.expected?.id != id) {
            failOpen()
            return
        }
        binding = ActivityProfileEditBinding.inflate(layoutInflater)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(binding.root)
        val night = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, binding.root).apply {
            isAppearanceLightStatusBars = !night
            isAppearanceLightNavigationBars = !night
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(binding.root)
        binding.pageHeading.pageToolbar.title = getString(R.string.profiles_edit_title)
        binding.pageHeading.pageToolbar.navigationIcon = AppCompatResources.getDrawable(this, R.drawable.ui_ic_back)
        binding.pageHeading.pageToolbar.setNavigationIconTint(getColor(R.color.ui_text_primary))
        binding.pageHeading.pageToolbar.setNavigationContentDescription(R.string.profiles_back)
        binding.pageHeading.pageToolbar.setNavigationOnClickListener { requestLeave() }
        val fields = listOf(
            binding.profileEditHost to "HOME_HOSTNAME", binding.profileEditPort to "SSL_PORT",
            binding.profileEditHub to "HOME_HUB", binding.profileEditUsername to "HOME_USERNAME",
            binding.profileEditPassword to "HOME_PASSWORD",
        )
        configureInput(binding.profileEditName)
        binding.profileEditName.setText(model.name)
        binding.profileEditName.doAfterTextChanged { model.name = it?.toString().orEmpty() }
        fields.forEach { (input, key) ->
            configureInput(input)
            input.setText(model.fields[key].orEmpty())
            input.doAfterTextChanged {
                model.fields[key] = it?.toString().orEmpty()
                if (key == "HOME_HOSTNAME" || key == "SSL_PORT") {
                    if (model.hubCertificateApproval?.endpoint != draftEndpoint()) model.hubCertificateApproval = null
                    renderCertificateCard()
                    updateHubLookup()
                }
            }
        }
        binding.profilePortBox.setEndIconOnClickListener { choosePort() }
        binding.profileAuthMode.setOnClickListener { chooseAuthentication() }
        binding.profileClientCertificateFile.setOnClickListener { selectClientCertificate.launch(arrayOf("*/*")) }
        binding.profileClientPrivateKeyFile.setOnClickListener { selectClientKey.launch(arrayOf("*/*")) }
        renderAuthentication()
        binding.profileHubBox.setEndIconOnClickListener { openHubOptions() }
        binding.profileHubBox.isEndIconVisible = false
        binding.profileCertificateManage.setOnClickListener { showCertificate() }
        binding.profileEditSave.setOnClickListener { saveAndFinish() }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { requestLeave() }
        })
        updateAvailability()
    }

    private fun configureInput(input: EditText) {
        input.isSaveEnabled = false
        input.isSaveFromParentEnabled = false
        input.importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun choosePort() {
        if (portDialog?.isShowing == true) return
        val input = binding.profileEditPort
        val current = input.text?.toString()?.toIntOrNull()
        val selected = PORT_PRESETS.indexOfFirst { it.first == current }
        val choices = PORT_PRESETS.map { (port, service) -> "$port ($service)" } + getString(R.string.profile_port_custom)
        portDialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pref_ssl_port)
            .setSingleChoiceItems(choices.toTypedArray(), if (selected < 0) PORT_PRESETS.size else selected) { dialog, index ->
                dialog.dismiss()
                if (index < PORT_PRESETS.size) {
                    input.setText(PORT_PRESETS[index].first.toString())
                } else {
                    input.requestFocus()
                    input.selectAll()
                    input.post { WindowCompat.getInsetsController(window, input).show(WindowInsetsCompat.Type.ime()) }
                }
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun chooseAuthentication() {
        if (authDialog?.isShowing == true) return
        val modes = NativeAuthMode.entries
        val choices = modes.map { getString(authenticationLabel(it)) } + getString(R.string.profile_auth_smartcard_unavailable)
        val adapter = object : ArrayAdapter<String>(this, android.R.layout.select_dialog_singlechoice, choices) {
            override fun areAllItemsEnabled() = false
            override fun isEnabled(position: Int) = position < modes.size
        }
        authDialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.profile_auth_type)
            .setSingleChoiceItems(adapter, model.authMode.ordinal) { dialog, index ->
                dialog.dismiss()
                model.authMode = modes[index]
                renderAuthentication()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun authenticationLabel(mode: NativeAuthMode): Int = when (mode) {
        NativeAuthMode.ANONYMOUS -> R.string.profile_auth_anonymous
        NativeAuthMode.STANDARD_PASSWORD -> R.string.profile_auth_standard_password
        NativeAuthMode.EXTERNAL_PASSWORD -> R.string.profile_auth_external_password
        NativeAuthMode.CLIENT_CERTIFICATE -> R.string.profile_auth_client_certificate
    }

    private fun renderAuthentication() {
        val mode = model.authMode
        binding.profileAuthMode.setText(authenticationLabel(mode))
        binding.profilePasswordLabel.isVisible = mode.usesPassword
        binding.profilePasswordBox.isVisible = mode.usesPassword
        binding.profileClientCertificateFields.isVisible = mode == NativeAuthMode.CLIENT_CERTIFICATE
        binding.profileClientCertificateFile.setText(if (model.fields["HOME_CLIENT_CERT"].isNullOrEmpty())
            R.string.profile_auth_select_certificate else R.string.profile_auth_replace_certificate)
        binding.profileClientPrivateKeyFile.setText(if (model.fields["HOME_CLIENT_KEY"].isNullOrEmpty())
            R.string.profile_auth_select_key else R.string.profile_auth_replace_key)
    }

    private fun loadClientCredential(uri: Uri, privateKey: Boolean) {
        if (!::binding.isInitialized || credentialImport?.isActive == true || model.authMode != NativeAuthMode.CLIENT_CERTIFICATE) return
        binding.profileEditSave.isEnabled = false
        credentialImport = lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = checkNotNull(contentResolver.openInputStream(uri)).use {
                        it.readNBytes(ClientCertificateFiles.MAX_FILE_BYTES + 1)
                    }
                    try {
                        if (privateKey) {
                            val der = ClientCertificateFiles.privateKey(bytes).encoded
                            try { ClientKeyProtection.encrypt(der) } finally { der.fill(0) }
                        } else {
                            val certificate = ClientCertificateFiles.certificate(bytes)
                            certificate.checkValidity()
                            Base64.getEncoder().encodeToString(certificate.encoded)
                        }
                    } finally { bytes.fill(0) }
                }
            }
            credentialImport = null
            if (model.authMode == NativeAuthMode.CLIENT_CERTIFICATE) {
                result.onSuccess { model.fields[if (privateKey) "HOME_CLIENT_KEY" else "HOME_CLIENT_CERT"] = it }
                    .onFailure { toast(if (privateKey) R.string.profile_auth_invalid_key else R.string.profile_auth_invalid_certificate) }
                renderAuthentication()
            }
            updateAvailability()
        }
    }

    override fun onStart() {
        super.onStart()
        if (::binding.isInitialized) {
            store.preferences.registerOnSharedPreferenceChangeListener(listener)
            certificates.preferences.registerOnSharedPreferenceChangeListener(listener)
            main.post(refresh)
        }
    }

    override fun onStop() {
        cancelHubLookup()
        hubTarget = null
        if (::binding.isInitialized) {
            store.preferences.unregisterOnSharedPreferenceChangeListener(listener)
            certificates.preferences.unregisterOnSharedPreferenceChangeListener(listener)
        }
        main.removeCallbacks(refresh)
        super.onStop()
    }

    private fun busy(): Boolean = model.expected?.id == store.preferences.getString(ProfileStore.ACTIVE_ID_KEY, null) &&
        store.preferences.getBoolean("HOME_CONNECTOR", false)

    private fun updateAvailability() {
        if (!::binding.isInitialized || isFinishing || isDestroyed) return
        val id = model.expected?.id ?: return
        missing = runCatching { store.state().profiles.none { it.id == id } }.getOrDefault(true)
        binding.profileEditSave.isEnabled = !missing && !busy() && credentialImport?.isActive != true
        binding.profileEditNotice.setText(when {
            missing -> R.string.profiles_editor_missing
            busy() -> R.string.profiles_editor_busy
            else -> R.string.profiles_editor_notice
        })
        refreshCertificateState()
        updateHubLookup()
    }

    private fun refreshCertificateState() {
        val id = model.expected?.id ?: return
        val snapshot = runCatching { certificates.read(id) }.getOrNull()
        certificateReadFailed = snapshot == null || snapshot.profileId != id
        certificateSnapshot = snapshot?.takeIf { !certificateReadFailed }
        certificateEditorStale = !editorBaselineMatches()
        renderCertificateCard()
    }

    private fun editorBaselineMatches(): Boolean {
        val expected = model.expected ?: return false
        val latest = runCatching { store.readForEdit(expected.id) }.getOrNull() ?: return false
        return latest.id == expected.id && latest.name == expected.name && latest.values == expected.values
    }

    private fun draftEndpoint(): CertificateEndpoint? {
        val host = model.fields["HOME_HOSTNAME"].orEmpty().trim()
        val portText = model.fields["SSL_PORT"].orEmpty()
        if (portText.isEmpty() || portText.any { it !in '0'..'9' }) return null
        val port = portText.toIntOrNull() ?: return null
        if (host.any { it.isWhitespace() || it.isISOControl() || it in "/\\@?#" }) return null
        return runCatching { CertificateEndpoint.of(host, port) }.getOrNull()
    }

    private fun updateHubLookup(force: Boolean = false) {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) || isFinishing) return
        val profile = model.expected ?: return
        val target = draftEndpoint()?.takeIf { !missing && !certificateReadFailed }?.let { endpoint ->
            val pin = runCatching { certificates.lookupPin(profile, endpoint) }.getOrNull() ?: return@let null
            val approval = model.hubCertificateApproval?.takeIf { it.endpoint == endpoint && it.expectedPin == pin }
            HubTarget(endpoint, pin.ifEmpty { approval?.identity?.sha256.orEmpty() })
        }
        if (target == hubTarget && !force) return
        cancelHubLookup()
        hubTarget = target
        hubNames = emptyList()
        hubCertificate = null
        if (target == null) {
            showHubHint(R.string.profile_hub_manual)
            return
        }
        showHubHint(R.string.profile_hub_loading)
        val profileValues = model.expected?.values.orEmpty()
        val protocol = profileValues["SSL_VERSION"] as? String ?: "DEFAULT"
        val suites = if (profileValues["SSL_DO_SELECT_SUITES"] == true) {
            (profileValues["SSL_SUITES"] as? Set<*>)?.filterIsInstance<String>()?.toSet().orEmpty()
        } else null
        hubJob = lifecycleScope.launch {
            if (!force) delay(650)
            val probe = TapTlsPreflight(getSystemService(ConnectivityManager::class.java), diagnostic = { _, _, _ -> })
            hubProbe = probe
            val timeout = Runnable {
                cancelHubLookup()
                showHubHint(R.string.profile_hub_not_found, options = true)
            }
            main.postDelayed(timeout, 12_000)
            try {
                hubNames = runInterruptible(Dispatchers.IO) {
                    probe.listHubs(target.endpoint, target.pin, protocol, suites)
                }
                val hint = if (hubNames.isEmpty()) R.string.profile_hub_not_found else R.string.profile_hub_available
                showHubHint(hint, options = true)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                hubCertificate = generateSequence<Throwable>(error) { it.cause }.take(12)
                    .filterIsInstance<CertificateReviewException>().firstOrNull()
                    ?.takeIf { it.expectedSha256.isEmpty() }
                val hint = if (hubCertificate == null) R.string.profile_hub_not_found else R.string.profile_hub_review
                showHubHint(hint, options = true)
            } finally {
                main.removeCallbacks(timeout)
                if (hubProbe === probe) hubProbe = null
                runCatching(probe::close)
            }
        }
    }

    private fun cancelHubLookup() {
        hubJob?.cancel()
        hubJob = null
        hubProbe?.let { runCatching(it::close) }
        hubProbe = null
        hubDialog?.dismiss()
        hubDialog = null
    }

    private fun showHubHint(message: Int, options: Boolean = false) {
        binding.profileHubBox.helperText = getString(message)
        binding.profileHubBox.isEndIconVisible = options
    }

    private fun openHubOptions() {
        val target = hubTarget ?: return
        val names = hubNames
        val review = hubCertificate
        if (hubDialog?.isShowing == true) return
        val dialog = MaterialAlertDialogBuilder(this).setNegativeButton(R.string.action_cancel, null)
        when {
            names.isNotEmpty() -> dialog.setTitle(R.string.profile_hub_choices).setItems(names.toTypedArray()) { _, index ->
                if (hubTarget == target) binding.profileEditHub.setText(names[index])
            }
            review != null -> dialog.setTitle(R.string.profile_hub_review_title)
                .setMessage(getString(R.string.profile_hub_review_message, formatEndpoint(target.endpoint),
                    review.identity.sha256.chunked(2).joinToString(":").uppercase(Locale.ROOT)))
                .setPositiveButton(R.string.profile_hub_review_accept) { _, _ ->
                    rememberHubCertificate(target, review)
                }
            else -> { updateHubLookup(force = true); return }
        }
        hubDialog = dialog.show()
    }

    private fun rememberHubCertificate(target: HubTarget, review: CertificateReviewException) {
        val profile = model.expected ?: return
        val approval = HubCertificateApproval(target.endpoint, review.expectedSha256, review.identity)
        val accepted = hubTarget == target && draftEndpoint() == target.endpoint && !busy() &&
            review.identity.isValidAt(System.currentTimeMillis()) && runCatching {
                if (certificateSnapshot?.endpoint == target.endpoint) {
                    certificates.rememberHubCertificate(profile, approval)
                } else if (certificates.lookupPin(profile, target.endpoint) == approval.expectedPin) {
                    model.hubCertificateApproval = approval
                    true
                } else false
            }.getOrDefault(false)
        if (!accepted) {
            toast(R.string.profile_hub_remember_failed)
            updateAvailability()
            return
        }
        refreshCertificateState()
        updateHubLookup(force = true)
    }

    private fun renderCertificateCard() {
        if (!::binding.isInitialized || isFinishing || isDestroyed) return
        val snapshot = certificateSnapshot
        val draft = draftEndpoint()
        val stagedApproval = model.hubCertificateApproval?.takeIf { it.endpoint == draft && !certificateEditorStale }
        val endpoint = stagedApproval?.endpoint ?: snapshot?.endpoint
        val addressMatches = endpoint != null && draft == endpoint
        binding.profileCertificateStatus.setText(when {
            missing || certificateReadFailed -> R.string.profile_cert_read_failed
            stagedApproval != null -> R.string.profile_hub_certificate_verified
            snapshot?.pin.isNullOrEmpty() -> R.string.profile_cert_empty
            else -> R.string.profile_cert_saved
        })
        binding.profileCertificateEndpoint.text = if (endpoint == null) getString(R.string.profile_cert_endpoint_empty)
            else getString(R.string.profile_cert_endpoint, formatEndpoint(endpoint))
        binding.profileCertificateHint.setText(when {
            missing || certificateReadFailed -> R.string.profile_read_failed
            certificateEditorStale -> R.string.profile_cert_stale_editor
            stagedApproval != null -> R.string.profile_hub_certificate_pending_save
            !addressMatches -> R.string.profile_cert_save_endpoint
            busy() -> R.string.profile_cert_busy
            snapshot?.pin.isNullOrEmpty() -> R.string.profile_cert_first_connection
            else -> R.string.profile_cert_manage_hint
        })
        val viewable = !missing && !certificateReadFailed && !certificateEditorStale &&
            stagedApproval == null && addressMatches && !snapshot?.pin.isNullOrEmpty()
        binding.profileCertificateManage.isEnabled = viewable
        certificateDialog?.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = viewable && !busy() &&
            sameCertificate(certificateDialogSnapshot, snapshot)
    }

    private fun canViewSnapshot(expected: ProfileCertificateSnapshot): Boolean {
        if (model.expected?.id != expected.profileId || expected.endpoint == null || expected.pin.isEmpty() ||
            draftEndpoint() != expected.endpoint || !editorBaselineMatches()) return false
        val current = runCatching { certificates.read(expected.profileId) }.getOrNull() ?: return false
        return sameCertificate(current, expected)
    }

    private fun canForgetSnapshot(expected: ProfileCertificateSnapshot): Boolean = !busy() && canViewSnapshot(expected)

    private fun sameCertificate(first: ProfileCertificateSnapshot?, second: ProfileCertificateSnapshot?): Boolean =
        first != null && second != null && first.profileId == second.profileId && first.endpoint == second.endpoint && first.pin == second.pin

    private fun showCertificate() {
        refreshCertificateState()
        val snapshot = certificateSnapshot ?: return
        if (certificateDialog?.isShowing == true || !canViewSnapshot(snapshot)) return
        val endpoint = snapshot.endpoint ?: return
        val profile = model.expected ?: return
        val fingerprint = snapshot.pin.chunked(2).joinToString(":").uppercase(Locale.ROOT)
        val message = getString(R.string.profile_cert_details, profile.name, formatEndpoint(endpoint), fingerprint) +
            if (busy()) "\n\n${getString(R.string.profile_cert_busy)}" else ""
        val details = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.profile_cert_title)
            .setMessage(message)
            .setNegativeButton(R.string.profile_cert_close, null)
            .setPositiveButton(R.string.profile_cert_forget_action, null)
            .create()
        certificateDialog = details
        certificateDialogSnapshot = snapshot
        details.setOnDismissListener {
            if (certificateDialog === details) {
                certificateDialog = null
                certificateDialogSnapshot = null
            }
        }
        details.setOnShowListener {
            details.findViewById<android.widget.TextView>(android.R.id.message)?.setTextIsSelectable(true)
            details.getButton(AlertDialog.BUTTON_POSITIVE).apply {
                isEnabled = canForgetSnapshot(snapshot)
                val themedColors = textColors
                setTextColor(ColorStateList(
                    arrayOf(intArrayOf(android.R.attr.state_enabled), intArrayOf()),
                    intArrayOf(ContextCompat.getColor(this@ProfileEditActivity, R.color.ui_error),
                        themedColors.getColorForState(intArrayOf(-android.R.attr.state_enabled), themedColors.defaultColor)),
                ))
                setOnClickListener {
                    isEnabled = false
                    // One confirmation for exactly the UUID, endpoint and fingerprint displayed.
                    val removed = runCatching {
                        canForgetSnapshot(snapshot) && certificates.forget(snapshot)
                    }.getOrDefault(false)
                    if (removed) {
                        details.dismiss()
                        toast(R.string.profile_cert_forgotten)
                    } else {
                        // Keep the viewed fingerprint and original confirmation on failure.
                        toast(R.string.profile_cert_forget_failed)
                    }
                    refreshCertificateState()
                    if (!removed) isEnabled = canForgetSnapshot(snapshot)
                }
            }
        }
        details.show()
    }

    private fun formatEndpoint(endpoint: CertificateEndpoint): String {
        val host = if (':' in endpoint.host) "[${endpoint.host}]" else endpoint.host
        return "$host:${endpoint.port}"
    }

    private fun saveAndFinish() {
        val expected = model.expected ?: return
        if (credentialImport?.isActive == true) return
        binding.profileNameBox.error = null
        binding.profileHostBox.error = null
        binding.profilePortBox.error = null
        val name = model.name.trim()
        if (name.isBlank() || name.length > 64 || name.any(Char::isISOControl)) {
            binding.profileNameBox.error = getString(R.string.profile_name_invalid)
            return
        }
        val port = model.fields["SSL_PORT"].orEmpty()
        val numericPort = port.toIntOrNull()
        if (port.isEmpty() || port.any { it !in '0'..'9' } || numericPort == null || numericPort !in 1..65535) {
            binding.profilePortBox.error = getString(R.string.error_invalid_port)
            return
        }
        val host = model.fields["HOME_HOSTNAME"].orEmpty()
        if (host.isNotBlank() && (host.contains("://") || host.contains('/'))) {
            binding.profileHostBox.error = getString(R.string.profiles_host_invalid)
            return
        }
        if (missing || busy()) { updateAvailability(); toast(R.string.profiles_editor_busy_or_missing); return }
        if (model.authMode == NativeAuthMode.CLIENT_CERTIFICATE && !clientCredentialPairMatches()) {
            toast(R.string.profile_auth_pair_mismatch)
            return
        }
        // Password is preserved byte-for-character as entered; no trim, logs or saved state.
        val approval = model.hubCertificateApproval?.takeIf { it.endpoint == draftEndpoint() }
        runCatching {
            val values = model.mergedValues()
            if (approval == null) store.saveProfile(expected, name, values)
            else certificates.saveProfileWithHubCertificate(expected, name, values, approval)
        }.onSuccess {
            toast(R.string.profiles_editor_saved)
            finish()
        }.onFailure {
            val latest = runCatching { store.readForEdit(expected.id) }.getOrNull()
            toast(when {
                latest == null -> R.string.profiles_editor_missing
                latest.name != expected.name || latest.values != expected.values -> R.string.profiles_editor_conflict
                busy() -> R.string.profiles_editor_busy
                approval != null -> R.string.profile_hub_certificate_save_failed
                else -> R.string.profile_operation_failed
            })
            // Keep the exact draft and baseline; never overwrite it with refreshed store values.
            updateAvailability()
        }
    }

    private fun clientCredentialPairMatches(): Boolean {
        val certificate = model.fields["HOME_CLIENT_CERT"].orEmpty()
        val privateKey = model.fields["HOME_CLIENT_KEY"].orEmpty()
        if (certificate.isEmpty() || privateKey.isEmpty()) return true
        return runCatching {
            val der = ClientKeyProtection.decrypt(privateKey)
            try { ClientCertificateFiles.matches(Base64.getDecoder().decode(certificate), der) }
            finally { der.fill(0) }
        }.getOrDefault(false)
    }

    private fun requestLeave() {
        if (!model.dirty) { finish(); return }
        if (leaveDialog?.isShowing == true) return
        leaveDialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.profile_unsaved_title)
            .setMessage(R.string.profiles_editor_leave)
            .setPositiveButton(R.string.action_save) { _, _ -> saveAndFinish() }
            .setNegativeButton(R.string.profiles_discard_back) { _, _ -> finish() }
            .setNeutralButton(R.string.action_cancel, null)
            .create().also { dialog ->
                dialog.setOnDismissListener { if (leaveDialog === dialog) leaveDialog = null }
                dialog.show()
            }
    }

    override fun onDestroy() {
        leaveDialog?.dismiss()
        leaveDialog = null
        portDialog?.dismiss()
        portDialog = null
        authDialog?.dismiss()
        authDialog = null
        certificateDialog?.dismiss()
        certificateDialog = null
        certificateDialogSnapshot = null
        main.removeCallbacksAndMessages(null)
        if (isFinishing && ::model.isInitialized) {
            if (::binding.isInitialized) listOf(binding.profileEditName, binding.profileEditHost, binding.profileEditPort,
                binding.profileEditHub, binding.profileEditUsername, binding.profileEditPassword).forEach { it.text?.clear() }
            model.clearSensitive()
        }
        super.onDestroy()
    }

    private fun failOpen() { toast(R.string.profile_read_failed); finish() }
    private fun toast(message: Int) { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
    companion object {
        const val EXTRA_PROFILE_ID = "profile_editor_uuid"
        private val PORT_PRESETS = listOf(8888 to "PX-VPN", 443 to "HTTPS", 992 to "TelnetS", 5555 to "SE-VPN")
    }
}
