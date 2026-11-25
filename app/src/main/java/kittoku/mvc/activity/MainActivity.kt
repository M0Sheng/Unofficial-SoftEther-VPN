package kittoku.mvc.activity

import android.Manifest
import android.animation.ValueAnimator
import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.content.res.AppCompatResources
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.preference.PreferenceManager
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.transition.MaterialFadeThrough
import com.google.android.material.transition.MaterialSharedAxis
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.databinding.ActivityMainBinding
import kittoku.mvc.fragment.AboutFragment
import kittoku.mvc.fragment.DashboardFragment
import kittoku.mvc.fragment.HomeFragment
import kittoku.mvc.fragment.SettingFragment
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getBooleanPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.privacy.PrivacyDisclosure
import kittoku.mvc.profile.ConnectionPhase
import kittoku.mvc.profile.putConnectionStatus
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.service.ACTION_VPN_CONNECT
import kittoku.mvc.service.ACTION_VPN_DISCONNECT
import kittoku.mvc.service.SoftEtherVpnService
import kittoku.mvc.tls.CertificateTrustStore
import java.util.UUID
import kittoku.mvc.profile.ConnectionRecovery
import kittoku.mvc.profile.RecoveryAction
import kittoku.mvc.service.ACTION_VPN_RECOVER

class MainActivity : AppCompatActivity() {
    private val certificateStore by lazy { CertificateTrustStore(this) }
    private val settings by lazy { PreferenceManager.getDefaultSharedPreferences(this) }
    private val profiles by lazy { ProfileStore(this) }
    private val mainHandler = Handler(Looper.getMainLooper())
    private var resumed = false
    private val recoveryListener: () -> Unit = { mainHandler.post { recoverConnection() } }
    private var awaitingVpnPermission = false
    private var permissionRequestId: String? = null
    private var permissionProfileId: String? = null
    private var currentPage = R.id.nav_dashboard
    private lateinit var binding: ActivityMainBinding
    private lateinit var navigation: NavigationBarView
    private val certificateListener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
        mainHandler.post { showPendingCertificate() }
    }
    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        // A cancelled request must not reconnect after the user has pressed Stop.
        if (awaitingVpnPermission) {
            val requestId = permissionRequestId
            val profileId = permissionProfileId
            awaitingVpnPermission = false
            permissionRequestId = null
            permissionProfileId = null
            val matches = requestId != null && profileId != null &&
                settings.getString(PERMISSION_REQUEST_KEY, null) == requestId &&
                settings.getString(PERMISSION_PROFILE_KEY, null) == profileId &&
                settings.getString(ProfileStore.ACTIVE_ID_KEY, null) == profileId &&
                ConnectionRecovery.isLocalPermission(settings, requestId, profileId) &&
                getBooleanPrefValue(MvcPreference.HOME_CONNECTOR, settings)
            if (requestId != null && profileId != null) clearPermissionToken(requestId, profileId)
            // A late A -> B -> A result must not act on a newer request or another profile.
            if (!matches) return@registerForActivityResult
            if (result.resultCode == Activity.RESULT_OK) {
                sendServiceAction(ACTION_VPN_CONNECT)
            } else {
                settings.edit().putBoolean(MvcPreference.HOME_CONNECTOR.name, false)
                    .putConnectionStatus(ConnectionPhase.FAILED, getString(R.string.status_permission_denied)).apply()
            }
        }
    }
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        val message = if (granted) R.string.profile_runtime_notification_allowed
            else R.string.profile_runtime_notification_blocked
        DiagnosticLog.record("INFO", "NOTIFICATION", getString(message))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportFragmentManager.setFragmentResultListener(PrivacyDisclosureDialog.RESULT, this) { _, result ->
            if (result.getBoolean(PrivacyDisclosureDialog.ACCEPTED)) startConnection()
        }
        awaitingVpnPermission = savedInstanceState?.getBoolean("vpn_permission_pending") ?: false
        permissionRequestId = savedInstanceState?.getString("vpn_permission_request_id")
        permissionProfileId = savedInstanceState?.getString("vpn_permission_profile_id")
        if (awaitingVpnPermission && !ConnectionRecovery.isLocalPermission(settings, permissionRequestId, permissionProfileId)) {
            awaitingVpnPermission = false; permissionRequestId = null; permissionProfileId = null
        }
        val initialPage = if (intent.getBooleanExtra(EXTRA_OPEN_PROFILES, false)) R.id.nav_configuration else R.id.nav_dashboard
        val restoredPage = savedInstanceState?.getInt("main_page", initialPage) ?: initialPage
        currentPage = when (restoredPage) {
            R.id.nav_configuration, R.id.nav_settings, PAGE_ABOUT -> restoredPage
            else -> R.id.nav_dashboard
        }
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityMainBinding.inflate(layoutInflater)
        val useRail = resources.getBoolean(R.bool.main_navigation_rail)
        binding.navigationRail.isVisible = useRail
        binding.bottomNavigation.isVisible = !useRail
        navigation = if (useRail) binding.navigationRail else binding.bottomNavigation
        navigation.inflateMenu(R.menu.main_navigation)
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
            // Material navigation also handles system bars by default; consume after
            // applying them here so the gesture inset is not added twice.
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(binding.root)
        binding.pageHeading.pageToolbar.setNavigationOnClickListener {
            openPage(if (currentPage == PAGE_ABOUT) R.id.nav_settings else R.id.nav_dashboard)
        }
        navigation.selectedItemId = if (currentPage == PAGE_ABOUT) R.id.nav_settings else currentPage
        navigation.setOnItemSelectedListener {
            if (supportFragmentManager.isStateSaved) false
            else {
                openPage(it.itemId)
                true
            }
        }
        openPage(currentPage)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (currentPage == PAGE_ABOUT) openPage(R.id.nav_settings)
                else if (currentPage != R.id.nav_dashboard) openPage(R.id.nav_dashboard)
                else {
                    isEnabled = false
                    try { onBackPressedDispatcher.onBackPressed() }
                    finally { isEnabled = true }
                }
            }
        })
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    internal fun openPage(page: Int) {
        if (supportFragmentManager.isStateSaved) return
        val previousPage = currentPage
        currentPage = page
        val tag = "main_page_$page"
        val shown = supportFragmentManager.findFragmentById(R.id.mainContent)
        val pageIsShown = when (page) {
            R.id.nav_configuration -> shown is HomeFragment
            R.id.nav_settings -> shown is SettingFragment
            PAGE_ABOUT -> shown is AboutFragment
            else -> shown is DashboardFragment
        }
        if (!pageIsShown || previousPage != page) {
            val fragment: Fragment = when (page) {
                R.id.nav_configuration -> HomeFragment()
                R.id.nav_settings -> SettingFragment()
                PAGE_ABOUT -> AboutFragment()
                else -> DashboardFragment()
            }
            if (shown != null) {
                val animate = binding.mainContent.isLaidOut && ValueAnimator.areAnimatorsEnabled()
                when {
                    !animate -> shown.exitTransition = null
                    (shown is SettingFragment && page == PAGE_ABOUT) ||
                        (shown is AboutFragment && page == R.id.nav_settings) -> {
                        val forward = page == PAGE_ABOUT
                        shown.exitTransition = MaterialSharedAxis(MaterialSharedAxis.X, forward)
                        fragment.enterTransition = MaterialSharedAxis(MaterialSharedAxis.X, forward)
                    }
                    else -> {
                        shown.exitTransition = MaterialFadeThrough()
                        fragment.enterTransition = MaterialFadeThrough()
                    }
                }
            }
            supportFragmentManager.beginTransaction()
                .setReorderingAllowed(true)
                .replace(R.id.mainContent, fragment, tag)
                .commit()
        }
        val navItem = if (page == PAGE_ABOUT) R.id.nav_settings else page
        if (navigation.selectedItemId != navItem) {
            navigation.menu.findItem(navItem)?.isChecked = true
        }
        updateToolbar()
    }

    private fun updateToolbar() {
        binding.pageHeading.pageToolbar.title = when (currentPage) {
            R.id.nav_configuration -> getString(R.string.ui_nav_configuration)
            R.id.nav_settings -> getString(R.string.ui_nav_settings)
            PAGE_ABOUT -> getString(R.string.tab_about)
            else -> getString(R.string.ui_nav_dashboard)
        }
        binding.pageHeading.pageToolbar.navigationIcon =
            if (currentPage == PAGE_ABOUT) AppCompatResources.getDrawable(this, R.drawable.ui_ic_back) else null
    }

    internal fun toggleVpnConnection() {
        if (getBooleanPrefValue(MvcPreference.HOME_CONNECTOR, settings) || awaitingVpnPermission) {
            awaitingVpnPermission = false
            permissionRequestId = null
            permissionProfileId = null
            settings.edit().remove(PERMISSION_PROFILE_KEY).remove(PERMISSION_REQUEST_KEY)
                .putBoolean(MvcPreference.HOME_CONNECTOR.name, false).apply()
            sendServiceAction(ACTION_VPN_DISCONNECT)
            return
        }
        startConnection()
    }

    private fun startConnection() {
        if (awaitingVpnPermission || getBooleanPrefValue(MvcPreference.HOME_CONNECTOR, settings)) return
        try {
            val profileId = profiles.ensureInitialized()
            if (profileId == null) {
                openPage(R.id.nav_configuration)
                return
            }
            PrivacyDisclosure.pendingConnection(this, settings)?.let {
                PrivacyDisclosureDialog.show(supportFragmentManager, it)
                return
            }
            val requestId = UUID.randomUUID().toString()
            permissionRequestId = requestId
            permissionProfileId = profileId
            ConnectionRecovery.permissionStarted(settings, requestId, profileId)
            settings.edit().putString(PERMISSION_PROFILE_KEY, profileId).putString(PERMISSION_REQUEST_KEY, requestId)
                .putBoolean(MvcPreference.HOME_CONNECTOR.name, true)
                .putConnectionStatus(ConnectionPhase.CONNECTING, getString(R.string.status_connecting)).apply()
            if (getStringPrefValue(MvcPreference.BACKEND_MODE, settings) != "TUN") {
                clearPermissionToken(requestId, profileId)
                permissionRequestId = null
                permissionProfileId = null
                sendServiceAction(ACTION_VPN_CONNECT)
            } else {
                val permission = VpnService.prepare(this)
                if (permission == null) {
                    clearPermissionToken(requestId, profileId)
                    permissionRequestId = null
                    permissionProfileId = null
                    sendServiceAction(ACTION_VPN_CONNECT)
                }
                else { awaitingVpnPermission = true; vpnPermission.launch(permission) }
            }
        } catch (error: Exception) {
            val requestId = permissionRequestId
            val profileId = permissionProfileId
            if (requestId != null && profileId != null) clearPermissionToken(requestId, profileId)
            awaitingVpnPermission = false
            permissionRequestId = null
            permissionProfileId = null
            connectionStartFailed(error)
        }
    }

    private fun clearPermissionToken(requestId: String, profileId: String) {
        if (settings.getString(PERMISSION_REQUEST_KEY, null) == requestId &&
            settings.getString(PERMISSION_PROFILE_KEY, null) == profileId) {
            settings.edit().remove(PERMISSION_PROFILE_KEY).remove(PERMISSION_REQUEST_KEY).apply()
        }
        ConnectionRecovery.permissionFinished(settings, requestId, profileId)
    }

    private fun sendServiceAction(action: String) {
        var request: kittoku.mvc.profile.ProfileConnectionRequest? = null
        try {
            val intent = Intent(this, SoftEtherVpnService::class.java).setAction(action)
            if (action == ACTION_VPN_CONNECT) {
                val profileId = profiles.ensureInitialized()
                if (profileId == null) {
                    openPage(R.id.nav_configuration)
                    return
                }
                request = kittoku.mvc.profile.ProfileConnectionRequest.reserve(settings, profileId)
                intent.putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_PROFILE, request.profileId)
                    .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_NONCE, request.nonce)
                    .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, request.sequence)
            } else if (action == ACTION_VPN_DISCONNECT) {
                val sequence = kittoku.mvc.profile.ProfileConnectionRequest.reserveStop(settings)
                intent.putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, sequence)
            }
            if (action == ACTION_VPN_DISCONNECT) startService(intent) else startForegroundService(intent)
        } catch (error: Exception) {
            if (request == null || kittoku.mvc.profile.ProfileConnectionRequest.cancel(settings, request)) connectionStartFailed(error)
        }
    }

    private fun connectionStartFailed(error: Exception) {
        DiagnosticLog.record("ERROR", "UI_START", getString(R.string.profile_runtime_connection_command_failed, error.stackTraceToString()))
        settings.edit().putBoolean(MvcPreference.HOME_CONNECTOR.name, false)
            .putConnectionStatus(ConnectionPhase.FAILED, getString(R.string.ui_start_failed, error.javaClass.simpleName)).apply()
        Toast.makeText(this, R.string.ui_start_failed_hint, Toast.LENGTH_LONG).show()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("vpn_permission_pending", awaitingVpnPermission)
        outState.putString("vpn_permission_request_id", permissionRequestId)
        outState.putString("vpn_permission_profile_id", permissionProfileId)
        outState.putInt("main_page", currentPage)
        super.onSaveInstanceState(outState)
    }

    override fun onStart() {
        super.onStart()
        certificateStore.preferences.registerOnSharedPreferenceChangeListener(certificateListener)
        settings.registerOnSharedPreferenceChangeListener(certificateListener)
        ConnectionRecovery.addListener(recoveryListener)
    }
    override fun onPostResume() { super.onPostResume(); resumed = true; recoverConnection(); showPendingCertificate() }
    override fun onPause() { resumed = false; super.onPause() }
    override fun onStop() {
        certificateStore.preferences.unregisterOnSharedPreferenceChangeListener(certificateListener)
        settings.unregisterOnSharedPreferenceChangeListener(certificateListener)
        ConnectionRecovery.removeListener(recoveryListener)
        super.onStop()
    }
    override fun onDestroy() {
        if (isFinishing && awaitingVpnPermission) {
            val request = permissionRequestId; val profile = permissionProfileId
            if (request != null && profile != null && ConnectionRecovery.isLocalPermission(settings, request, profile) &&
                settings.getString(PERMISSION_REQUEST_KEY, null) == request && settings.getString(PERMISSION_PROFILE_KEY, null) == profile) {
                clearPermissionToken(request, profile)
                settings.edit().putBoolean("HOME_CONNECTOR", false).apply()
            }
        }
        mainHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun recoverConnection() {
        if (!resumed) return
        when (val action = ConnectionRecovery.plan(settings, {
            PrivacyDisclosure.pendingConnection(this, settings) != null ||
                getStringPrefValue(MvcPreference.BACKEND_MODE, settings) == "TUN" && VpnService.prepare(this) != null
        }, getString(R.string.status_disconnected))) {
            is RecoveryAction.Resume -> try {
                DiagnosticLog.record("INFO", "RECOVERY", getString(R.string.profile_runtime_recovery_request, action.accepted.sequence))
                settings.edit().putConnectionStatus(ConnectionPhase.CONNECTING, getString(R.string.status_connecting)).apply()
                startForegroundService(Intent(this, SoftEtherVpnService::class.java).setAction(ACTION_VPN_RECOVER)
                    .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, action.accepted.sequence))
            } catch (error: Exception) {
                ConnectionRecovery.recoveryLaunchFailed(settings, action.accepted.sequence, getString(R.string.status_disconnected))
                DiagnosticLog.record("WARN", "RECOVERY", getString(R.string.profile_runtime_recovery_launch_failed, error.javaClass.simpleName))
            }
            RecoveryAction.Reset -> {
                DiagnosticLog.record("DEBUG", "RECOVERY", getString(R.string.profile_runtime_recovery_reset))
                kittoku.mvc.service.VpnTileService.refresh(this)
            }
            RecoveryAction.None -> Unit
        }
    }

    private fun showPendingCertificate() {
        if (!resumed || supportFragmentManager.isStateSaved) return
        val candidate = certificateStore.pending()
        val existing = supportFragmentManager.findFragmentByTag(CertificateDialogFragment.TAG) as? CertificateDialogFragment
        if (existing != null && (candidate == null || !existing.matches(candidate.requestId))) existing.dismissNow()
        if (candidate != null && supportFragmentManager.findFragmentByTag(CertificateDialogFragment.TAG) == null) {
            CertificateDialogFragment.newInstance(candidate.requestId).showNow(supportFragmentManager, CertificateDialogFragment.TAG)
        }
    }

    internal companion object {
        const val PAGE_ABOUT = -1
        const val EXTRA_OPEN_PROFILES = "kittoku.mvc.open_profiles"
        private const val PERMISSION_PROFILE_KEY = "VPN_PERMISSION_PROFILE_ID"
        private const val PERMISSION_REQUEST_KEY = "VPN_PERMISSION_REQUEST_ID"
    }
}
