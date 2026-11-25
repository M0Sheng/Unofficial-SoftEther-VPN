package kittoku.mvc.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.annotation.MainThread
import androidx.preference.PreferenceManager
import kittoku.mvc.BuildConfig
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModeMigration
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.control.ConnectionContext
import kittoku.mvc.control.TunConnection
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.control.TrafficMeter
import kittoku.mvc.control.NativeSessionController
import kittoku.mvc.nativecore.NativeAuthMode
import kittoku.mvc.nativecore.NativeSessionFailure
import kittoku.mvc.nativecore.softEtherErrorMessage
import kittoku.mvc.network.PhysicalUnderlayLostException
import kittoku.mvc.network.PhysicalUnderlayMonitor
import kittoku.mvc.network.physicalUnderlay
import kittoku.mvc.routing.AppRoutingSettings
import kittoku.mvc.routing.RoutingBypassSettings
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getIntPrefValue
import kittoku.mvc.preference.accessor.setBooleanPrefValue
import kittoku.mvc.profile.ConnectionPhase
import kittoku.mvc.profile.putConnectionStatus
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.privacy.PrivacyDisclosure
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import kittoku.mvc.tls.CertificateReviewException
import kittoku.mvc.tls.CertificateTrustStore
import kittoku.mvc.profile.ProfileConnectionRequest
import kittoku.mvc.profile.ConnectionRecovery
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.routing.TunDestinationSettings

internal const val ACTION_VPN_CONNECT = "${BuildConfig.APPLICATION_ID}.connect"
internal const val ACTION_VPN_DISCONNECT = "${BuildConfig.APPLICATION_ID}.disconnect"
internal const val ACTION_VPN_RECOVER = "${BuildConfig.APPLICATION_ID}.recover"
// Preserve Android's existing channel settings when upgrading.
private enum class SessionNotice(val channel: String, val id: Int, val importance: Int) {
    Active("DISCONNECT", 3, NotificationManager.IMPORTANCE_LOW),
    Failure("ERROR", 1, NotificationManager.IMPORTANCE_DEFAULT),
    Certificate("CERTIFICATE", 4, NotificationManager.IMPORTANCE_DEFAULT),
}

internal class SoftEtherVpnService : VpnService() {
    private val notices by lazy { getSystemService(NotificationManager::class.java) }
    private val mainHandler = Handler(Looper.getMainLooper())
    private var client: TunConnection? = null
    private var nativeClient: NativeSessionController? = null
    @Volatile private var currentBridge: ConnectionContext? = null
    private var desiredConnection = false
    private var currentRequestSequence = 0L
    private var underlayMonitor: PhysicalUnderlayMonitor? = null
    private var waitingForUnderlay = false
    private val underlayDeadline = Runnable {
        if (waitingForUnderlay && desiredConnection) {
            finishSession(IOException(getString(R.string.network_runtime_error_enable_underlay_network)))
        }
    }
    private var networkHandoverAttempts = 0
    private var connectedSince = 0L
    private var latestStartId = 0
    private val runtimeOwner = Any()
    private var currentDiagnosticSessionId = ""
    @Volatile private var notificationStatus = ""
    private var localeTags = ""
    private val trafficTicker = object : Runnable {
        override fun run() {
            if (!showsTraffic()) return
            publishNotice(SessionNotice.Active, ongoingNotification())
            mainHandler.postDelayed(this, 1000L)
        }
    }
    private val featureListener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == "SHOW_NOTIFICATION_TRAFFIC") mainHandler.post { refreshActiveNotification() }
        if (key == ProfileStore.ACTIVE_ID_KEY || key == ProfileStore.ACTIVATION_KEY ||
            key == ProfileConnectionRequest.SEQUENCE_KEY) mainHandler.post {
            if (waitingForUnderlay && !ConnectionRecovery.wanted(prefs, currentRequestSequence)) {
                finishSession(null)
            }
        }
        if (key == "NATIVE_REMOTE_MANAGEMENT" || key == "NATIVE_REMOTE_PASSWORD_CHANGED_AT") mainHandler.post {
            if (desiredConnection && currentBridge?.backendMode == "ROOT_NATIVE") {
                nativeClient?.kill(IOException(getString(R.string.error_management_settings_changed)))
            }
        }
    }
    private val prefs by lazy { PreferenceManager.getDefaultSharedPreferences(this) }

    override fun onCreate() {
        super.onCreate()
        localeTags = resources.configuration.locales.toLanguageTags()
        runningService = this
        ConnectionRecovery.serviceCreated(runtimeOwner)
        prefs.registerOnSharedPreferenceChangeListener(featureListener)
        val appName = getString(R.string.app_name)
        notices.createNotificationChannels(SessionNotice.entries.map { entry ->
            NotificationChannel(entry.channel, appName, entry.importance)
        })
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        val currentLocaleTags = resources.configuration.locales.toLanguageTags()
        if (localeTags == currentLocaleTags) return
        localeTags = currentLocaleTags
        if (!desiredConnection) return

        when (ConnectionPhase.read(prefs)) {
            ConnectionPhase.CONNECTED -> {
                if (client?.refreshStatus() != true && nativeClient?.refreshStatus() != true) {
                    updateStatus(getString(R.string.status_connected))
                }
            }
            ConnectionPhase.MANAGEMENT -> updateStatus(getString(R.string.native_management_running))
            ConnectionPhase.CONNECTING -> updateStatus(getString(
                if (waitingForUnderlay && networkHandoverAttempts != 0) R.string.network_runtime_status_network_switch_waiting
                else R.string.status_connecting,
            ))
            else -> refreshActiveNotification()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        val requestedSequence = intent?.getLongExtra(ProfileConnectionRequest.EXTRA_SEQUENCE, -1L) ?: -1L
        var retriedAcceptedStart = false
        if (intent?.action == ACTION_VPN_CONNECT) {
            val profileId = intent.getStringExtra(ProfileConnectionRequest.EXTRA_PROFILE)
            val nonce = intent.getStringExtra(ProfileConnectionRequest.EXTRA_NONCE)
            if (!ProfileConnectionRequest.consumeAndAccept(prefs, profileId, nonce, requestedSequence)) {
                // Android retries the original intent if the process died before onStartCommand returned.
                retriedAcceptedStart = (flags and START_FLAG_RETRY) != 0 &&
                    ConnectionRecovery.matchesAcceptedStartRetry(prefs, profileId, requestedSequence)
                if (!retriedAcceptedStart) {
                    DiagnosticLog.record("DEBUG", "RECOVERY", getString(R.string.network_runtime_log_recovery_request_ignored, requestedSequence))
                    if (!desiredConnection) stopSelf(startId)
                    return if (desiredConnection) START_STICKY else START_NOT_STICKY
                }
            }
        }
        if (intent?.action == ACTION_VPN_DISCONNECT) {
            val sequence = if (intent.hasExtra(ProfileConnectionRequest.EXTRA_SEQUENCE))
                intent.getLongExtra(ProfileConnectionRequest.EXTRA_SEQUENCE, -1L)
                else ProfileConnectionRequest.reserveStop(prefs)
            if (ProfileConnectionRequest.stopAffectsSession(currentRequestSequence, sequence)) {
                // A newer queued Start or permission request owns the persisted state.
                // Still release an older running session, without cancelling that newer request.
                disconnect(preserveRequest = prefs.getBoolean("HOME_CONNECTOR", false), startId = startId, alreadyReserved = true)
            }
            return if (desiredConnection) START_STICKY else START_NOT_STICKY
        }
        val recovery = intent == null || intent.action == ACTION_VPN_RECOVER || retriedAcceptedStart
        val sequence = if (intent == null) ConnectionRecovery.accepted(prefs)?.sequence ?: -1L else requestedSequence
        if (recovery) {
            // A sticky restart and a launcher recovery can be queued together.
            // A live service already owns its session.
            if (desiredConnection) return START_STICKY
            val needsConsent = ConnectionRecovery.accepted(prefs)?.sequence == sequence &&
                (PrivacyDisclosure.pendingConnection(this, prefs) != null ||
                    getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == "TUN" && VpnService.prepare(this) != null)
            if (needsConsent || !ConnectionRecovery.consumeRecovery(prefs, runtimeOwner, sequence)) {
                DiagnosticLog.record("DEBUG", "RECOVERY", getString(R.string.network_runtime_log_recovery_request_not_claimed, sequence, needsConsent))
                ConnectionRecovery.resetAbandoned(prefs, runtimeOwner, getString(R.string.status_disconnected),
                    expectedSequence = if (needsConsent) sequence else null)
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        val connect = intent?.action == ACTION_VPN_CONNECT || recovery
        if (connect) {
            currentRequestSequence = sequence
            ConnectionRecovery.serviceAccepted(runtimeOwner, currentRequestSequence)
            TrafficMeter.reset()
            prefs.edit().putLong("HOME_SESSION_STARTED_AT", System.currentTimeMillis()).apply()
            val startReason = when {
                retriedAcceptedStart -> getString(R.string.network_runtime_log_recovery_request_retried)
                intent == null -> getString(R.string.network_runtime_log_recovery_service_recreated)
                recovery -> getString(R.string.network_runtime_log_recovery_foreground_request)
                else -> getString(R.string.network_runtime_log_user_connect_requested)
            }
            DiagnosticLog.record("INFO", "SERVICE", "$startReason；sequence=$currentRequestSequence")
            if (!recovery) {
                CertificateTrustStore(this).clearPending()
                notices.cancel(SessionNotice.Certificate.id)
            }
            notices.cancel(SessionNotice.Failure.id)
            desiredConnection = true
            networkHandoverAttempts = 0
            updateStatus(getString(R.string.status_connecting), ConnectionPhase.CONNECTING)
            beForegrounded(getString(R.string.status_connecting))
            stopActiveSession()
            startUnderlayMonitor()
            return START_STICKY
        }
        disconnect()
        return START_NOT_STICKY
    }

    private fun startSession(underlay: Network) {
        if (!desiredConnection) return
        if (!ConnectionRecovery.wanted(prefs, currentRequestSequence)) {
            desiredConnection = false
            stopUnderlayMonitor()
            ConnectionRecovery.sessionEnded(prefs, runtimeOwner, currentRequestSequence)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(latestStartId)
            return
        }
        var owner: TunConnection? = null
        var nativeOwner: NativeSessionController? = null
        connectedSince = 0L
        try {
            check(PrivacyDisclosure.pendingConnection(this, prefs) == null) { getString(R.string.privacy_connection_required) }
            val profiles = ProfileStore(this)
            val profileId = checkNotNull(profiles.ensureInitialized()) {
                getString(R.string.ui_no_profile_explanation)
            }
            val backendMode = BackendModeMigration.migrate(this, prefs)
            currentDiagnosticSessionId = DiagnosticLog.startSession(
                backendMode,
                getStringPrefValue(MvcPreference.HOME_HOSTNAME, prefs),
                getIntPrefValue(MvcPreference.SSL_PORT, prefs),
                getStringPrefValue(MvcPreference.HOME_HUB, prefs))
            val tap = backendMode == BackendModePolicy.ROOT_NATIVE
            TrafficMeter.useSession(currentDiagnosticSessionId, available = !tap)
            AppRoutingSettings(this).requireSupportedBackend(backendMode)
            if (!tap && !prefs.contains(TunDestinationSettings.MODE_KEY)) {
                RoutingBypassSettings(this).validate()
            }
            val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val handler = CoroutineExceptionHandler { _, throwable ->
                nativeOwner?.kill(throwable) ?: owner?.kill(throwable)
            }
            val bridge = ConnectionContext(this, scope, handler, currentDiagnosticSessionId, prefs, backendMode, profileId,
                profiles, underlay)
            DiagnosticLog.redactCredentials(bridge.clientUsername, bridge.clientPassword)
            currentBridge = bridge
            setBooleanPrefValue(true, MvcPreference.HOME_CONNECTOR, prefs)
            if (tap) {
                val created = NativeSessionController(bridge)
                nativeOwner = created
                nativeClient = created
                created.run()
            } else {
                val created = TunConnection(bridge)
                owner = created
                client = created
                created.run()
            }
        } catch (error: Throwable) {
            DiagnosticLog.record("ERROR", "CONFIG", getString(R.string.network_runtime_log_connection_init_failed, error.stackTraceToString()), currentDiagnosticSessionId)
            desiredConnection = false
            stopUnderlayMonitor()
            val ownsState = ConnectionRecovery.sessionEnded(prefs, runtimeOwner, currentRequestSequence)
            val message = error.message ?: getString(R.string.error_invalid_configuration)
            if (ownsState) {
                updateStatus(message, ConnectionPhase.FAILED)
                notifyError(message)
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(latestStartId)
        }
    }

    private fun updateStatus(message: String, phase: ConnectionPhase = ConnectionPhase.read(prefs)) {
        if (getStringPrefValue(MvcPreference.HOME_STATUS, prefs) != message) {
            DiagnosticLog.record("INFO", "STATUS", message, currentDiagnosticSessionId)
        }
        prefs.edit().putConnectionStatus(phase, message).apply()
        notificationStatus = message.lineSequence().firstOrNull().orEmpty()
        refreshActiveNotification()
        VpnTileService.refresh(this)
    }

    internal fun updateConnectionStatus(bridge: ConnectionContext, message: String, current: () -> Boolean = { true }) {
        mainHandler.post {
            if (current() && currentBridge === bridge && desiredConnection &&
                ConnectionRecovery.wanted(prefs, currentRequestSequence)) updateStatus(message)
        }
    }

    internal fun onSessionConnected(owner: TunConnection, ipv4Only: Boolean) {
        mainHandler.post {
            if (client !== owner || !desiredConnection || !ConnectionRecovery.wanted(prefs, currentRequestSequence)) return@post
            connectedSince = SystemClock.elapsedRealtime()
            DiagnosticLog.record("INFO", "SERVICE", getString(R.string.network_runtime_log_tun_interface_established), currentDiagnosticSessionId)
            prefs.edit().putString(ConnectionPhase.KEY, ConnectionPhase.CONNECTED.name).apply()
            beForegrounded(getString(if (ipv4Only) R.string.tun_ipv6_ipv4_only else R.string.status_connected))
        }
    }

    internal fun onSessionEnded(owner: TunConnection, error: Throwable?) {
        finishAfterNetworkCallbacks(error) { client === owner }
    }

    internal fun onNativeSessionConnected(owner: NativeSessionController) {
        mainHandler.post {
            if (nativeClient !== owner || !desiredConnection || !ConnectionRecovery.wanted(prefs, currentRequestSequence)) return@post
            connectedSince = SystemClock.elapsedRealtime()
            prefs.edit().putString(ConnectionPhase.KEY, ConnectionPhase.CONNECTED.name).apply()
            beForegrounded(getString(if (owner.hasNetworkAddress) R.string.status_connected else R.string.vpn_virtual_adapter_waiting))
        }
    }

    internal fun onNativeManagementStarted(owner: NativeSessionController) {
        mainHandler.post {
            if (nativeClient !== owner || !desiredConnection || !ConnectionRecovery.wanted(prefs, currentRequestSequence)) return@post
            if (ConnectionPhase.read(prefs) != ConnectionPhase.CONNECTED) {
                prefs.edit().putString(ConnectionPhase.KEY, ConnectionPhase.MANAGEMENT.name).apply()
                beForegrounded(getString(R.string.native_management_running))
            }
        }
    }

    internal fun onNativeManagedAccountDisconnected(owner: NativeSessionController) {
        mainHandler.post {
            if (nativeClient !== owner || !desiredConnection || !ConnectionRecovery.wanted(prefs, currentRequestSequence)) return@post
            updateStatus(getString(R.string.native_management_running), ConnectionPhase.MANAGEMENT)
        }
    }

    internal fun onNativeSessionEnded(owner: NativeSessionController, error: Throwable?) {
        finishAfterNetworkCallbacks(error) { nativeClient === owner }
    }

    private fun finishAfterNetworkCallbacks(error: Throwable?, ownsSession: () -> Boolean) {
        // A socket can fail before Android delivers the network change to the service.
        val delay = if (error !is PhysicalUnderlayLostException && couldBeLinkFailure(error)) {
            PhysicalUnderlayMonitor.SETTLE_MILLIS
        } else 0L
        mainHandler.postDelayed({ if (ownsSession()) finishSession(error) }, delay)
    }

    private fun couldBeLinkFailure(error: Throwable?): Boolean =
        error is IOException ||
            (error is NativeSessionFailure && !error.peerClosed && error.code in NETWORK_FAILURE_CODES)

    private fun finishSession(error: Throwable?) {
        val endedBridge = currentBridge
        client = null
        nativeClient = null
        currentBridge = null
        val causes = generateSequence(error) { it.cause }.take(12).toList()
        val review = causes.filterIsInstance<CertificateReviewException>().firstOrNull()
        val underlayLost = causes.any { it is PhysicalUnderlayLostException }
        if (review == null && endedBridge?.nativeManagementOnly == false &&
            (underlayLost || (couldBeLinkFailure(error) && physicalLinkChanged(endedBridge.underlyingNetwork))) &&
            beginUnderlayHandover()) return
        val pending = if (desiredConnection && ConnectionRecovery.wanted(prefs, currentRequestSequence) && endedBridge != null && review != null) {
            runCatching { CertificateTrustStore(this).beginReview(endedBridge.profileId, endedBridge.serverHostname,
                endedBridge.serverPort, endedBridge.backendMode, review) }.getOrNull()
        } else null
        val phase = when {
            pending != null -> ConnectionPhase.CERTIFICATE_REVIEW
            error != null -> ConnectionPhase.FAILED
            else -> ConnectionPhase.DISCONNECTED
        }
        val reason = when {
            pending != null -> getString(R.string.certificate_waiting)
            error is NativeSessionFailure -> describeNativeFailure(error, endedBridge?.authentication?.mode)
            causes.any { it is CertificateExpiredException || it is CertificateNotYetValidException } ->
                getString(R.string.certificate_invalid_date)
            causes.any { it is SSLHandshakeException || it is SSLPeerUnverifiedException } ->
                getString(R.string.error_preflight_tls)
            causes.any { it is UnknownHostException } -> getString(R.string.error_preflight_dns)
            causes.any { it is ConnectException } -> getString(R.string.error_preflight_connect)
            causes.any { it is SocketTimeoutException } -> getString(R.string.error_preflight_timeout)
            else -> error?.message ?: getString(R.string.status_disconnected)
        }
        DiagnosticLog.record(
            when (phase) {
                ConnectionPhase.CERTIFICATE_REVIEW -> "WARN"
                ConnectionPhase.FAILED -> "ERROR"
                else -> "INFO"
            },
            if (pending != null) "CERTIFICATE" else "SERVICE", getString(R.string.network_runtime_log_session_ended, reason),
            endedBridge?.sessionId ?: currentDiagnosticSessionId,
        )
        desiredConnection = false
        stopUnderlayMonitor()
        mainHandler.removeCallbacks(trafficTicker)
        TrafficMeter.useSession("")
        if (ConnectionRecovery.sessionEnded(prefs, runtimeOwner, currentRequestSequence)) {
            updateStatus(reason, phase)
            if (pending != null) notifyCertificateReview()
            else if (error != null) notifyError(reason)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(latestStartId)
    }

    private fun describeNativeFailure(error: NativeSessionFailure, mode: NativeAuthMode?): String {
        val meaning = when {
            error.peerClosed || error.code == 11 -> getString(R.string.error_server_disconnected)
            error.code == 9 && mode != null -> getString(when (mode) {
                NativeAuthMode.ANONYMOUS -> R.string.profile_auth_anonymous_rejected
                NativeAuthMode.CLIENT_CERTIFICATE -> R.string.profile_auth_certificate_rejected
                else -> R.string.error_authentication_failed
            })
            else -> softEtherErrorMessage(this, error.code)
        }
        return getString(R.string.error_native_session_status, error.code, meaning.removeSuffix("。").removeSuffix("."))
    }

    internal fun onUnderlyingNetworkLost(bridge: ConnectionContext, network: Network) {
        mainHandler.post {
            if (desiredConnection && currentBridge === bridge) {
                val error = PhysicalUnderlayLostException(network)
                client?.kill(error)
                nativeClient?.kill(error)
            }
        }
    }

    private fun startUnderlayMonitor() {
        val monitor = PhysicalUnderlayMonitor(getSystemService(ConnectivityManager::class.java), mainHandler,
            ::onPhysicalLinkChanged)
        underlayMonitor = monitor
        waitForPhysicalLink()
        try {
            monitor.start()
        } catch (error: RuntimeException) {
            finishSession(error)
        }
    }

    private fun onPhysicalLinkChanged(network: Network?) {
        if (!desiredConnection || !ConnectionRecovery.wanted(prefs, currentRequestSequence)) return
        if (waitingForUnderlay) {
            if (network == null || getSystemService(ConnectivityManager::class.java).physicalUnderlay(network) == null) return
            waitingForUnderlay = false
            mainHandler.removeCallbacks(underlayDeadline)
            updateStatus(getString(R.string.status_connecting), ConnectionPhase.CONNECTING)
            startSession(network)
        } else {
            val bridge = currentBridge ?: return
            if (!bridge.nativeManagementOnly && bridge.underlyingNetwork != network) {
                val error = PhysicalUnderlayLostException(bridge.underlyingNetwork)
                client?.kill(error)
                nativeClient?.kill(error)
            }
        }
    }

    private fun physicalLinkChanged(previous: Network): Boolean =
        underlayMonitor?.let { it.readyNetwork != previous } == true ||
            getSystemService(ConnectivityManager::class.java).physicalUnderlay(previous) == null

    private fun waitForPhysicalLink() {
        waitingForUnderlay = true
        mainHandler.removeCallbacks(underlayDeadline)
        mainHandler.postDelayed(underlayDeadline, UNDERLAY_WAIT_MILLIS)
    }

    private fun beginUnderlayHandover(): Boolean {
        val monitor = underlayMonitor ?: return false
        if (!desiredConnection || !ConnectionRecovery.wanted(prefs, currentRequestSequence)) return false
        if (connectedSince != 0L && SystemClock.elapsedRealtime() - connectedSince >= UNDERLAY_STABLE_MILLIS) {
            networkHandoverAttempts = 0
        }
        if (networkHandoverAttempts >= MAX_HANDOVER_ATTEMPTS) return false
        networkHandoverAttempts++
        TrafficMeter.useSession("")
        updateStatus(getString(R.string.network_runtime_status_network_switch_waiting), ConnectionPhase.CONNECTING)
        waitForPhysicalLink()
        monitor.dispatchAfterSettling()
        return true
    }

    private fun stopUnderlayMonitor() {
        waitingForUnderlay = false
        mainHandler.removeCallbacks(underlayDeadline)
        underlayMonitor?.close()
        underlayMonitor = null
    }

    private fun stopActiveSession() {
        stopUnderlayMonitor()
        val previous = client
        val previousNative = nativeClient
        client = null
        nativeClient = null
        currentBridge = null
        previous?.kill(null)
        previousNative?.kill(null)
    }

    private fun disconnect(preserveRequest: Boolean = false, startId: Int? = null, alreadyReserved: Boolean = false) {
        if (!preserveRequest && !alreadyReserved) ProfileConnectionRequest.reserveStop(prefs)
        if (!preserveRequest) {
            prefs.edit().remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID")
                .remove("VPN_PERMISSION_REQUEST_ID").remove(ProfileConnectionRequest.PROFILE_KEY)
                .remove(ProfileConnectionRequest.NONCE_KEY).apply()
        }
        DiagnosticLog.record("INFO", "SERVICE", getString(R.string.network_runtime_log_user_disconnect_requested), currentDiagnosticSessionId)
        if (!preserveRequest) {
            prefs.edit().putLong("HOME_SESSION_STARTED_AT", 0L).apply()
            CertificateTrustStore(this).clearPending()
        }
        notices.cancel(SessionNotice.Certificate.id)
        desiredConnection = false
        ConnectionRecovery.sessionEnded(prefs, runtimeOwner, currentRequestSequence)
        mainHandler.removeCallbacks(trafficTicker)
        TrafficMeter.useSession("")
        stopActiveSession()
        if (!preserveRequest) {
            setBooleanPrefValue(false, MvcPreference.HOME_CONNECTOR, prefs)
            updateStatus(getString(R.string.status_disconnected), ConnectionPhase.DISCONNECTED)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (startId == null) stopSelf() else stopSelf(startId)
    }

    private fun beForegrounded(text: String) {
        notificationStatus = text
        startForeground(SessionNotice.Active.id, ongoingNotification())
        scheduleTraffic()
    }

    private fun refreshActiveNotification() {
        if (!desiredConnection) return
        publishNotice(SessionNotice.Active, ongoingNotification())
        scheduleTraffic()
    }

    private fun showsTraffic() = desiredConnection && ConnectionPhase.read(prefs) == ConnectionPhase.CONNECTED &&
        (client?.hasNetworkAddress == true || nativeClient?.hasNetworkAddress == true) &&
        prefs.getBoolean("SHOW_NOTIFICATION_TRAFFIC", false)

    private fun scheduleTraffic() {
        mainHandler.removeCallbacks(trafficTicker)
        if (showsTraffic()) mainHandler.postDelayed(trafficTicker, 1000L)
    }

    private fun ongoingNotification(): Notification {
        val disconnectIntent = PendingIntent.getService(this, 0,
            Intent(this, SoftEtherVpnService::class.java).setAction(ACTION_VPN_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val openIntent = PendingIntent.getActivity(this, 0,
            Intent(this, kittoku.mvc.activity.MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val traffic = if (showsTraffic()) TrafficMeter.snapshot() else null
        val title = traffic?.notificationText() ?: getString(R.string.app_name)
        val details = traffic?.let { "$notificationStatus\n${it.totalsText()}" } ?: notificationStatus
        val action = Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ui_ic_disconnect),
            getString(R.string.action_disconnect), disconnectIntent).build()
        return Notification.Builder(this, SessionNotice.Active.channel)
            .setSmallIcon(R.drawable.ic_lan_bridge)
            .setContentTitle(title)
            .setContentText(if (traffic == null) notificationStatus else null)
            .setStyle(Notification.BigTextStyle().bigText(details))
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent).setOngoing(true)
            .addAction(action)
            .build()
    }

    private fun notifyError(message: String) {
        val failure = Notification.Builder(this, SessionNotice.Failure.channel)
            .setSmallIcon(R.drawable.ic_lan_bridge).setContentTitle(getString(R.string.app_name))
            .setContentText(message).setStyle(Notification.BigTextStyle().bigText(message))
            .setAutoCancel(true).build()
        publishNotice(SessionNotice.Failure, failure)
    }

    private fun notifyCertificateReview() {
        val open = PendingIntent.getActivity(this, SessionNotice.Certificate.id,
            Intent(this, kittoku.mvc.activity.MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val review = Notification.Builder(this, SessionNotice.Certificate.channel)
            .setSmallIcon(R.drawable.ic_lan_bridge)
            .setContentTitle(getString(R.string.certificate_first_title))
            .setContentText(getString(R.string.certificate_waiting))
            .setContentIntent(open).setAutoCancel(true).build()
        publishNotice(SessionNotice.Certificate, review)
    }
    private fun publishNotice(kind: SessionNotice, notification: Notification) {
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            notices.notify(kind.id, notification)
        }
    }
    override fun onRevoke() {
        val backend = currentBridge?.backendMode ?: getStringPrefValue(MvcPreference.BACKEND_MODE, prefs)
        DiagnosticLog.record("WARN", "SERVICE", getString(R.string.network_runtime_log_android_vpn_revoked, backend), currentDiagnosticSessionId)
        // This backend is an Ethernet device, independent of Android's TUN grant.
        // VpnService's default onRevoke would stop even this root-owned service.
        if (desiredConnection && backend == "ROOT_NATIVE") return
        disconnect()
        super.onRevoke()
    }
    override fun onDestroy() {
        if (runningService === this) runningService = null
        prefs.unregisterOnSharedPreferenceChangeListener(featureListener)
        mainHandler.removeCallbacks(trafficTicker)
        TrafficMeter.useSession("")
        DiagnosticLog.record("INFO", "SERVICE", getString(R.string.network_runtime_log_connection_service_destroyed), currentDiagnosticSessionId)
        desiredConnection = false
        stopActiveSession()
        ConnectionRecovery.serviceDestroyed(runtimeOwner)
        VpnTileService.refresh(this)
        super.onDestroy()
    }

    companion object {
        private const val MAX_HANDOVER_ATTEMPTS = 3
        private const val UNDERLAY_WAIT_MILLIS = 30_000L
        private const val UNDERLAY_STABLE_MILLIS = 10_000L
        private val NETWORK_FAILURE_CODES = setOf(1, 3, 13) // Connect failed, disconnected, session timeout.
        private var runningService: SoftEtherVpnService? = null

        @MainThread
        fun currentPhase(prefs: android.content.SharedPreferences, enabled: Boolean): ConnectionPhase {
            val phase = ConnectionPhase.read(prefs)
            if (!enabled) return when (phase) {
                ConnectionPhase.FAILED, ConnectionPhase.CERTIFICATE_REVIEW -> phase
                else -> ConnectionPhase.DISCONNECTED
            }
            val service = runningService
            if (service == null || !service.desiredConnection ||
                !ConnectionRecovery.wanted(prefs, service.currentRequestSequence)) return ConnectionPhase.CONNECTING
            return when (phase) {
                ConnectionPhase.CONNECTED, ConnectionPhase.MANAGEMENT -> phase
                else -> ConnectionPhase.CONNECTING
            }
        }

        @MainThread
        fun currentInterfaceName(): String? {
            val service = runningService ?: return null
            if (!service.desiredConnection ||
                !ConnectionRecovery.wanted(service.prefs, service.currentRequestSequence)) return null
            return service.nativeClient?.interfaceName ?: service.client?.interfaceName
        }
    }
}
