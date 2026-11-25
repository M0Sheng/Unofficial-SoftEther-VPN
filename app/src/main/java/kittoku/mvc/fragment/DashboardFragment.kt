package kittoku.mvc.fragment

import android.animation.ValueAnimator
import android.content.SharedPreferences
import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.interpolator.view.animation.FastOutSlowInInterpolator
import androidx.preference.PreferenceManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.google.android.material.motion.MotionUtils
import com.google.android.material.progressindicator.CircularProgressIndicator
import kittoku.mvc.R
import kittoku.mvc.activity.MainActivity
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getBooleanPrefValue
import kittoku.mvc.preference.accessor.getIntPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.ConnectionPhase
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.profile.connectionStatus
import kittoku.mvc.service.SoftEtherVpnService
import java.util.Locale

internal class DashboardFragment : Fragment(R.layout.fragment_dashboard) {
    private val handler = Handler(Looper.getMainLooper())
    private val prefs by lazy { PreferenceManager.getDefaultSharedPreferences(requireContext()) }
    private val profiles by lazy { ProfileStore(requireContext()) }
    private var renderedPhase: ConnectionPhase? = null
    private val refreshConnection = Runnable { renderConnection() }
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || key in CONNECTION_KEYS) {
            handler.removeCallbacks(refreshConnection)
            handler.post(refreshConnection)
        }
    }
    private val ticker = object : Runnable {
        override fun run() {
            val root = view ?: return
            renderLiveFields(root, getBooleanPrefValue(MvcPreference.HOME_CONNECTOR, prefs))
            handler.postDelayed(this, 1000L)
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        view.findViewById<MaterialButton>(R.id.dashboardConnect).setOnClickListener {
            (activity as? MainActivity)?.toggleVpnConnection()
        }
    }

    override fun onStart() {
        super.onStart()
        prefs.registerOnSharedPreferenceChangeListener(listener)
        renderConnection()
        handler.postDelayed(ticker, 1000L)
    }
    override fun onStop() {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
        handler.removeCallbacksAndMessages(null)
        super.onStop()
    }

    override fun onDestroyView() {
        view?.findViewById<View>(R.id.dashboardConnectionGlyph)?.animate()?.cancel()
        renderedPhase = null
        super.onDestroyView()
    }

    private fun renderConnection() {
        val root = view ?: return
        if (!isAdded) return
        val state = runCatching { profiles.state() }
        val snapshot = state.getOrNull()
        val activeProfile = snapshot?.profiles?.firstOrNull { it.id == snapshot.activeId }
        val profileCard = root.findViewById<View>(R.id.dashboardProfileCard)
        val detailsCard = root.findViewById<View>(R.id.dashboardDetailsCard)
        if (snapshot != null && activeProfile == null) {
            profileCard.visibility = View.GONE
            detailsCard.visibility = View.GONE
            renderPhase(root, ConnectionPhase.DISCONNECTED)
            root.updateText(R.id.dashboardSummary, getString(R.string.ui_no_profile_explanation))
            root.findViewById<View>(R.id.dashboardSummary).visibility = View.VISIBLE
            renderAction(root, R.string.ui_open_profiles, R.drawable.ui_ic_config)
            return
        }
        profileCard.visibility = View.VISIBLE
        root.updateText(R.id.dashboardProfile, activeProfile?.name ?: getString(R.string.profile_read_failed))
        val enabled = getBooleanPrefValue(MvcPreference.HOME_CONNECTOR, prefs)
        val rawStatus = prefs.connectionStatus()
        val phase = SoftEtherVpnService.currentPhase(prefs, enabled)
        val status = rawStatus.ifBlank {
            getString(when (phase) {
                ConnectionPhase.DISCONNECTED -> R.string.status_disconnected
                ConnectionPhase.CONNECTING -> R.string.status_connecting
                ConnectionPhase.CONNECTED -> R.string.status_connected
                ConnectionPhase.MANAGEMENT -> R.string.native_management_running
                ConnectionPhase.CERTIFICATE_REVIEW -> R.string.certificate_waiting
                ConnectionPhase.FAILED -> R.string.ui_connection_failed
            })
        }
        val backend = getStringPrefValue(MvcPreference.BACKEND_MODE, prefs)
        val nativeManaged = backend == "ROOT_NATIVE" && prefs.getBoolean("NATIVE_MANAGEMENT_ONLY", false)
        val host = getStringPrefValue(MvcPreference.HOME_HOSTNAME, prefs)
        renderPhase(root, phase)
        val firstStatusLine = status.lineSequence().firstOrNull()?.trim().orEmpty()
        val isRedundantStatus = when (phase) {
            ConnectionPhase.DISCONNECTED -> firstStatusLine == getString(R.string.status_disconnected)
            ConnectionPhase.CONNECTED -> firstStatusLine == getString(R.string.status_connected) ||
                firstStatusLine == getString(R.string.vpn_virtual_adapter_connected)
            else -> false
        }
        val summary = when {
            firstStatusLine.isNotEmpty() && !isRedundantStatus -> firstStatusLine
            phase == ConnectionPhase.DISCONNECTED -> getString(when {
                nativeManaged -> R.string.ui_disconnected_management
                host.isBlank() -> R.string.ui_disconnected_configure
                else -> R.string.ui_disconnected_start
            })
            phase == ConnectionPhase.CONNECTED -> getString(R.string.ui_connected_routing)
            else -> ""
        }
        root.updateText(R.id.dashboardSummary, summary)
        root.findViewById<View>(R.id.dashboardSummary).visibility =
            if (summary.isEmpty()) View.INVISIBLE else View.VISIBLE
        root.updateText(R.id.dashboardStatus, status)
        detailsCard.visibility = if (rawStatus.isBlank()) View.GONE else View.VISIBLE
        val action = when {
            enabled -> R.string.ui_stop
            phase == ConnectionPhase.FAILED -> R.string.ui_retry_connection
            else -> R.string.ui_start
        }
        renderAction(root, action, R.drawable.ui_ic_power)
        val displayHost = if (host.contains(':') && !host.startsWith('[')) "[$host]" else host
        val port = getIntPrefValue(MvcPreference.SSL_PORT, prefs)
        root.updateText(R.id.dashboardServer, if (nativeManaged) getString(R.string.native_managed_endpoint)
            else if (host.isBlank()) getString(R.string.ui_not_configured) else "$displayHost:$port")
        root.updateText(R.id.dashboardHub, if (nativeManaged) getString(R.string.native_managed_endpoint)
            else getStringPrefValue(MvcPreference.HOME_HUB, prefs).ifBlank { getString(R.string.ui_not_configured) })
        root.updateText(R.id.dashboardBackend, getString(if (backend == "TUN") R.string.backend_mode_tun else R.string.backend_mode_native))
        renderLiveFields(root, enabled)
    }

    private fun renderAction(root: View, labelId: Int, iconId: Int) {
        root.findViewById<MaterialButton>(R.id.dashboardConnect).apply {
            val label = getString(labelId)
            if (!TextUtils.equals(text, label)) {
                text = label
                setIconResource(iconId)
            }
            if (!TextUtils.equals(contentDescription, label)) contentDescription = label
        }
    }

    private fun renderPhase(root: View, phase: ConnectionPhase) {
        if (renderedPhase == phase) return
        val animateChange = renderedPhase != null && root.isShown && root.isLaidOut &&
            ValueAnimator.areAnimatorsEnabled()
        renderedPhase = phase
        val title = when (phase) {
            ConnectionPhase.DISCONNECTED -> R.string.ui_disabled
            ConnectionPhase.CONNECTING -> R.string.ui_connecting
            ConnectionPhase.CONNECTED -> R.string.ui_enabled
            ConnectionPhase.MANAGEMENT -> R.string.ui_management_enabled
            ConnectionPhase.CERTIFICATE_REVIEW -> R.string.ui_certificate_review
            ConnectionPhase.FAILED -> R.string.ui_connection_failed
        }
        val progress = phase == ConnectionPhase.CONNECTING
        val context = root.context
        val (stateColor, containerColor) = when (phase) {
            ConnectionPhase.CONNECTED ->
                context.getColor(R.color.ui_vpn_enabled) to context.getColor(R.color.ui_vpn_enabled_container)
            ConnectionPhase.DISCONNECTED ->
                context.getColor(R.color.ui_vpn_disabled) to context.getColor(R.color.ui_vpn_disabled_container)
            ConnectionPhase.CONNECTING ->
                MaterialColors.getColor(root, com.google.android.material.R.attr.colorOnPrimaryContainer) to
                    MaterialColors.getColor(root, com.google.android.material.R.attr.colorPrimaryContainer)
            ConnectionPhase.MANAGEMENT ->
                MaterialColors.getColor(root, com.google.android.material.R.attr.colorOnSecondaryContainer) to
                    MaterialColors.getColor(root, com.google.android.material.R.attr.colorSecondaryContainer)
            ConnectionPhase.CERTIFICATE_REVIEW ->
                MaterialColors.getColor(root, com.google.android.material.R.attr.colorOnTertiaryContainer) to
                    MaterialColors.getColor(root, com.google.android.material.R.attr.colorTertiaryContainer)
            ConnectionPhase.FAILED ->
                MaterialColors.getColor(root, com.google.android.material.R.attr.colorOnErrorContainer) to
                    MaterialColors.getColor(root, com.google.android.material.R.attr.colorErrorContainer)
        }
        root.updateText(R.id.dashboardState, getString(title))
        root.findViewById<MaterialCardView>(R.id.dashboardConnectionCard).setCardBackgroundColor(containerColor)
        root.findViewById<TextView>(R.id.dashboardState).setTextColor(stateColor)
        root.findViewById<TextView>(R.id.dashboardSummary).setTextColor(stateColor)
        root.findViewById<ImageView>(R.id.dashboardConnectionIcon).apply {
            setImageResource(when (phase) {
                ConnectionPhase.CONNECTING -> R.drawable.ui_ic_shield_progress
                ConnectionPhase.CONNECTED -> R.drawable.ui_ic_shield
                ConnectionPhase.FAILED, ConnectionPhase.CERTIFICATE_REVIEW -> R.drawable.ui_ic_shield_alert
                else -> R.drawable.ui_ic_shield_off
            })
            imageTintList = ColorStateList.valueOf(stateColor)
        }
        root.findViewById<CircularProgressIndicator>(R.id.dashboardConnectionProgress).apply {
            if (progress) setIndicatorColor(containerColor)
            visibility = if (progress) View.VISIBLE else View.GONE
        }
        val glyph = root.findViewById<View>(R.id.dashboardConnectionGlyph)
        glyph.animate().cancel()
        val startingScale = if (animateChange) 0.9f else 1f
        glyph.scaleX = startingScale
        glyph.scaleY = startingScale
        if (animateChange) {
            val duration = MotionUtils.resolveThemeDuration(
                context, com.google.android.material.R.attr.motionDurationMedium1, 200
            )
            val interpolator = MotionUtils.resolveThemeInterpolator(
                context,
                com.google.android.material.R.attr.motionEasingStandardDecelerateInterpolator,
                FastOutSlowInInterpolator()
            )
            glyph.animate().scaleX(1f).scaleY(1f)
                .setDuration(duration.toLong()).setInterpolator(interpolator).start()
        }
    }

    private fun renderLiveFields(root: View, enabled: Boolean) {
        val interfaceName = if (enabled) SoftEtherVpnService.currentInterfaceName() else null
        root.updateText(R.id.dashboardInterface, interfaceName.orEmpty())
        root.findViewById<View>(R.id.dashboardInterfaceRow).visibility =
            if (interfaceName == null) View.GONE else View.VISIBLE
        val started = prefs.getLong(SESSION_STARTED, 0L)
        val now = System.currentTimeMillis()
        val elapsed = if (enabled && started > 0L && now >= started) {
            val seconds = (now - started) / 1000
            String.format(Locale.ROOT, "%02d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60)
        } else getString(R.string.ui_no_duration)
        root.updateText(R.id.dashboardElapsed, elapsed)
    }

    private fun View.updateText(id: Int, value: String) {
        val field = findViewById<TextView>(id)
        // Replacing selectable text resets the editor and can scroll its parent to the selection.
        if (!TextUtils.equals(field.text, value)) field.text = value
    }

    private companion object {
        const val SESSION_STARTED = "HOME_SESSION_STARTED_AT"
        val CONNECTION_KEYS = setOf(
            MvcPreference.HOME_CONNECTOR.name, MvcPreference.HOME_STATUS.name, ConnectionPhase.KEY,
            ConnectionPhase.STATUS_LOCALES_KEY,
            MvcPreference.HOME_HOSTNAME.name, MvcPreference.SSL_PORT.name,
            MvcPreference.HOME_HUB.name, MvcPreference.BACKEND_MODE.name,
            ProfileStore.ACTIVE_ID_KEY, ProfileStore.REGISTRY_KEY, "NATIVE_MANAGEMENT_ONLY", SESSION_STARTED,
        )
    }
}
