package kittoku.mvc.activity

import android.content.SharedPreferences
import android.content.res.Configuration
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.databinding.ActivityDestinationRoutingBinding
import kittoku.mvc.network.IPv6Policy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.routing.RoutingBypassSettings
import kittoku.mvc.routing.TunDestinationConfiguration
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationSettings
import kittoku.mvc.ui.configureRoutingToolbar

/** Edits address rules for the access method and profile active when this screen opens. */
class DestinationRoutingActivity : AppCompatActivity() {
    private lateinit var binding: ActivityDestinationRoutingBinding
    private val preferences by lazy { PreferenceManager.getDefaultSharedPreferences(this) }
    private val profiles by lazy { ProfileStore(this) }
    private val main = Handler(Looper.getMainLooper())
    private var expectedBackend = ""
    private val isTap get() = expectedBackend == BackendModePolicy.ROOT_NATIVE
    private var expectedProfileId = ""
    private var expectedActivation = ""
    private var selectedMode: TunDestinationMode? = null
    private var includeDraft = ""
    private var excludeDraft = ""
    private var legacy = false
    private var legacyDetails = ""
    private var loadError = ""
    private var stale = false
    private var rendering = false
    private val refresh = Runnable { if (!isDestroyed) render() }
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || key == ProfileStore.ACTIVE_ID_KEY || key == ProfileStore.ACTIVATION_KEY ||
            key == MvcPreference.BACKEND_MODE.name || key == MvcPreference.HOME_CONNECTOR.name ||
            key == IPv6Policy.TUN_PREFERENCE_KEY || key == IPv6Policy.PREFERENCE_KEY) {
            main.removeCallbacks(refresh)
            main.post(refresh)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityDestinationRoutingBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val night = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, binding.root).apply {
            isAppearanceLightStatusBars = !night
            isAppearanceLightNavigationBars = !night
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, keyboard.bottom))
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(binding.root)
        if (savedInstanceState == null) loadDraft() else restoreDraft(savedInstanceState)
        binding.pageHeading.pageToolbar.configureRoutingToolbar(
            R.string.destination_routing_title,
            if (isTap) R.string.destination_routing_tap_help_message else R.string.destination_routing_help_message
        ) { finish() }
        binding.destinationInclude.isSaveEnabled = false
        binding.destinationExclude.isSaveEnabled = false
        binding.destinationModes.isSaveFromParentEnabled = false
        binding.destinationInclude.setText(includeDraft)
        binding.destinationExclude.setText(excludeDraft)
        binding.destinationModes.addOnButtonCheckedListener { _, id, checked ->
            if (!checked || rendering) return@addOnButtonCheckedListener
            captureDrafts()
            selectedMode = when (id) {
                R.id.destinationModeExclude -> TunDestinationMode.EXCLUDE
                R.id.destinationModeInclude -> TunDestinationMode.INCLUDE
                R.id.destinationModeAll -> TunDestinationMode.ALL
                else -> return@addOnButtonCheckedListener
            }
            clearErrors()
            render()
        }
        binding.destinationSave.setOnClickListener { save() }
        render()
    }

    private fun loadDraft(): Unit = synchronized(ProfileStore.LOCK) {
        expectedProfileId = preferences.getString(ProfileStore.ACTIVE_ID_KEY, "").orEmpty()
        expectedActivation = preferences.getString(ProfileStore.ACTIVATION_KEY, "").orEmpty()
        expectedBackend = currentBackend()
        if (expectedProfileId.isBlank()) {
            selectedMode = TunDestinationMode.ALL
            return@synchronized
        }
        try {
            val current = TunDestinationSettings.read(preferences)
            val effective = current ?: TunDestinationSettings.effective(this, preferences, isTap)
            val legacyExcluded = if (effective == null) {
                RoutingBypassSettings(this).rawText()
            } else ""
            val draft = effective ?: TunDestinationSettings.draft(preferences, legacyExcluded)
            selectedMode = effective?.mode
            includeDraft = draft.includeRules
            excludeDraft = draft.excludeRules
            legacy = current == null && effective?.mode != TunDestinationMode.ALL
            if (legacy && !isTap) {
                val mode = getString(if (getStringPrefValue(MvcPreference.ROUTE_MODE, preferences) == "LAN")
                    R.string.tun_vpn_subnet_routes else R.string.tun_ipv4_default_route)
                val extra = getStringPrefValue(MvcPreference.LAN_ROUTES, preferences).ifBlank {
                    getString(R.string.destination_routing_none)
                }
                legacyDetails = getString(R.string.destination_routing_legacy_details, mode, extra,
                    legacyExcluded.ifBlank { getString(R.string.destination_routing_none) })
            }
        } catch (error: RuntimeException) {
            loadError = getString(R.string.destination_routing_load_error, error.message.orEmpty())
            includeDraft = runCatching { preferences.getString(TunDestinationSettings.INCLUDE_KEY, "").orEmpty() }.getOrDefault("")
            excludeDraft = runCatching { preferences.getString(TunDestinationSettings.EXCLUDE_KEY, "").orEmpty() }.getOrDefault("")
        }
    }

    private fun restoreDraft(state: Bundle) {
        expectedBackend = state.getString(STATE_BACKEND).orEmpty().ifBlank { BackendModePolicy.TUN }
        expectedProfileId = state.getString(STATE_PROFILE).orEmpty()
        expectedActivation = state.getString(STATE_ACTIVATION).orEmpty()
        selectedMode = state.getString(STATE_MODE)?.let { name -> TunDestinationMode.entries.firstOrNull { it.name == name } }
        includeDraft = state.getString(STATE_INCLUDE).orEmpty()
        excludeDraft = state.getString(STATE_EXCLUDE).orEmpty()
        legacy = state.getBoolean(STATE_LEGACY)
        legacyDetails = state.getString(STATE_LEGACY_DETAILS).orEmpty()
        loadError = state.getString(STATE_ERROR).orEmpty()
        stale = state.getBoolean(STATE_STALE)
    }

    private fun captureDrafts() {
        includeDraft = binding.destinationInclude.text?.toString().orEmpty()
        excludeDraft = binding.destinationExclude.text?.toString().orEmpty()
    }

    private fun currentBackend(): String = getStringPrefValue(MvcPreference.BACKEND_MODE, preferences)

    private fun identityMatches(): Boolean = expectedProfileId.isNotBlank() && expectedActivation.isNotBlank() &&
        preferences.getString(ProfileStore.ACTIVE_ID_KEY, null) == expectedProfileId &&
        preferences.getString(ProfileStore.ACTIVATION_KEY, null) == expectedActivation

    private fun render() {
        if (!::binding.isInitialized) return
        if (!identityMatches()) stale = true
        val backendMatches = currentBackend() == expectedBackend
        val editable = !stale && backendMatches
        binding.destinationModes.visibility = View.VISIBLE
        rendering = true
        when (selectedMode) {
            TunDestinationMode.EXCLUDE -> binding.destinationModes.check(R.id.destinationModeExclude)
            TunDestinationMode.INCLUDE -> binding.destinationModes.check(R.id.destinationModeInclude)
            TunDestinationMode.ALL -> binding.destinationModes.check(R.id.destinationModeAll)
            null -> binding.destinationModes.clearChecked()
        }
        rendering = false
        binding.destinationModeExclude.isEnabled = editable
        binding.destinationModeInclude.isEnabled = editable
        binding.destinationModeAll.isEnabled = editable
        binding.destinationIncludeBox.isEnabled = editable
        binding.destinationExcludeBox.isEnabled = editable
        binding.destinationIncludeBox.visibility = if (selectedMode == TunDestinationMode.INCLUDE) View.VISIBLE else View.GONE
        binding.destinationExcludeBox.visibility = if (selectedMode == TunDestinationMode.EXCLUDE) View.VISIBLE else View.GONE
        binding.destinationRetained.visibility = if (selectedMode == TunDestinationMode.ALL) View.VISIBLE else View.GONE
        binding.destinationModeHint.setText(when (selectedMode) {
            TunDestinationMode.EXCLUDE -> if (isTap) R.string.destination_routing_tap_exclude_hint else R.string.destination_routing_exclude_hint
            TunDestinationMode.INCLUDE -> if (isTap) R.string.destination_routing_tap_include_hint else R.string.destination_routing_include_hint
            TunDestinationMode.ALL -> if (isTap) R.string.destination_routing_tap_all_hint else R.string.destination_routing_all_hint
            null -> R.string.destination_routing_select_hint
        })
        binding.destinationLegacyCard.visibility = if (legacy || loadError.isNotEmpty()) View.VISIBLE else View.GONE
        binding.destinationLegacyBanner.text = if (loadError.isNotEmpty()) loadError
            else getString(R.string.destination_routing_legacy_banner)
        binding.destinationLegacyDetails.text = legacyDetails
        binding.destinationLegacyDetails.visibility = if (legacyDetails.isNotEmpty() && selectedMode == null) View.VISIBLE else View.GONE
        binding.destinationSupport.visibility = View.VISIBLE
        binding.destinationSupport.setText(if (isTap) {
            if (preferences.getBoolean(IPv6Policy.PREFERENCE_KEY, IPv6Policy.DEFAULT_FORWARDING))
                R.string.destination_routing_tap_ipv6_on else R.string.destination_routing_tap_ipv6_off
        } else {
            if (preferences.getBoolean(IPv6Policy.TUN_PREFERENCE_KEY, IPv6Policy.DEFAULT_FORWARDING))
                R.string.destination_routing_ipv6_on else R.string.destination_routing_ipv6_off
        })
        binding.destinationStatus.text = getString(when {
            expectedProfileId.isBlank() -> R.string.destination_routing_no_profile
            stale -> R.string.destination_routing_stale
            !backendMatches -> R.string.destination_routing_backend_changed
            selectedMode == null -> R.string.destination_routing_choose_before_save
            else -> R.string.destination_routing_save_hint
        })
        binding.destinationSave.isEnabled = editable && selectedMode != null
    }

    private fun clearErrors() {
        binding.destinationIncludeBox.error = null
        binding.destinationExcludeBox.error = null
        binding.destinationError.text = ""
        binding.destinationError.visibility = View.GONE
    }

    private fun save() {
        captureDrafts()
        clearErrors()
        render()
        if (!binding.destinationSave.isEnabled) return
        val mode = selectedMode ?: return
        try {
            val saved = synchronized(ProfileStore.LOCK) {
                if (!identityMatches() || currentBackend() != expectedBackend) {
                    false
                } else {
                    TunDestinationSettings.saveForProfile(profiles,
                        TunDestinationConfiguration(mode, includeDraft, excludeDraft), expectedProfileId, expectedActivation)
                }
            }
            if (!saved) {
                render()
                binding.destinationError.setText(R.string.destination_routing_save_failed)
                binding.destinationError.visibility = View.VISIBLE
                return
            }
            Toast.makeText(this, R.string.destination_routing_saved, Toast.LENGTH_SHORT).show()
            finish()
        } catch (error: IllegalArgumentException) {
            val message = error.message ?: getString(R.string.destination_routing_invalid)
            when (mode) {
                TunDestinationMode.INCLUDE -> binding.destinationIncludeBox.error = message
                TunDestinationMode.EXCLUDE -> binding.destinationExcludeBox.error = message
                TunDestinationMode.ALL -> {
                    binding.destinationError.text = message
                    binding.destinationError.visibility = View.VISIBLE
                }
            }
        } catch (_: RuntimeException) {
            binding.destinationError.setText(R.string.destination_routing_save_failed)
            binding.destinationError.visibility = View.VISIBLE
        }
    }

    override fun onStart() {
        super.onStart()
        preferences.registerOnSharedPreferenceChangeListener(listener)
        render()
    }

    override fun onStop() {
        preferences.unregisterOnSharedPreferenceChangeListener(listener)
        main.removeCallbacksAndMessages(null)
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        captureDrafts()
        outState.putString(STATE_BACKEND, expectedBackend)
        outState.putString(STATE_PROFILE, expectedProfileId)
        outState.putString(STATE_ACTIVATION, expectedActivation)
        outState.putString(STATE_MODE, selectedMode?.name)
        outState.putString(STATE_INCLUDE, includeDraft)
        outState.putString(STATE_EXCLUDE, excludeDraft)
        outState.putBoolean(STATE_LEGACY, legacy)
        outState.putString(STATE_LEGACY_DETAILS, legacyDetails)
        outState.putString(STATE_ERROR, loadError)
        outState.putBoolean(STATE_STALE, stale)
        super.onSaveInstanceState(outState)
    }

    private companion object {
        const val STATE_BACKEND = "destination.backend"
        const val STATE_PROFILE = "destination.profile"
        const val STATE_ACTIVATION = "destination.activation"
        const val STATE_MODE = "destination.mode"
        const val STATE_INCLUDE = "destination.include"
        const val STATE_EXCLUDE = "destination.exclude"
        const val STATE_LEGACY = "destination.legacy"
        const val STATE_LEGACY_DETAILS = "destination.legacy_details"
        const val STATE_ERROR = "destination.load_error"
        const val STATE_STALE = "destination.stale"
    }
}
