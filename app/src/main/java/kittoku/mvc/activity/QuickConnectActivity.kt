package kittoku.mvc.activity

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.preference.accessor.getBooleanPrefValue
import kittoku.mvc.preference.accessor.setBooleanPrefValue
import kittoku.mvc.privacy.PrivacyDisclosure
import kittoku.mvc.service.ACTION_VPN_CONNECT
import kittoku.mvc.service.ACTION_VPN_DISCONNECT
import kittoku.mvc.service.SoftEtherVpnService
import kittoku.mvc.service.ACTION_VPN_RECOVER
import kittoku.mvc.profile.ConnectionPhase
import kittoku.mvc.profile.ConnectionRecovery
import kittoku.mvc.profile.putConnectionStatus
import kittoku.mvc.profile.RecoveryAction

/** Non-exported foreground bridge for Quick Settings and Android's VPN permission prompt. */
class QuickConnectActivity : AppCompatActivity() {
    private val prefs by lazy { PreferenceManager.getDefaultSharedPreferences(this) }
    private var requestId = ""
    private var profileId = ""
    private fun isCurrentRequest() = requestId.isNotEmpty() && profileId.isNotEmpty() &&
        ConnectionRecovery.isLocalPermission(prefs, requestId, profileId) &&
        prefs.getString("QUICK_CONNECT_REQUEST_ID", "") == requestId &&
        prefs.getString(kittoku.mvc.profile.ProfileStore.ACTIVE_ID_KEY, "") == profileId &&
        prefs.getString("VPN_PERMISSION_PROFILE_ID", "") == profileId &&
        prefs.getString("VPN_PERMISSION_REQUEST_ID", "") == requestId &&
        getBooleanPrefValue(MvcPreference.HOME_CONNECTOR, prefs)
    private val permission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val current = isCurrentRequest()
        if (current && result.resultCode == Activity.RESULT_OK) send(ACTION_VPN_CONNECT)
        else {
            if (current) {
                prefs.edit().remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID")
                    .remove("VPN_PERMISSION_REQUEST_ID").putBoolean(MvcPreference.HOME_CONNECTOR.name, false)
                    .putConnectionStatus(ConnectionPhase.FAILED, getString(R.string.status_permission_denied)).apply()
            }
            finish()
        }
        ConnectionRecovery.permissionFinished(prefs, requestId, profileId)
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_quick_connect)
        supportFragmentManager.setFragmentResultListener(PrivacyDisclosureDialog.RESULT, this) { _, result ->
            if (result.getBoolean(PrivacyDisclosureDialog.ACCEPTED)) startConnection() else finish()
        }
        if (savedInstanceState != null) {
            requestId = savedInstanceState.getString("requestId").orEmpty()
            profileId = savedInstanceState.getString("profileId").orEmpty()
            if (requestId.isNotEmpty()) {
                if (!ConnectionRecovery.isLocalPermission(prefs, requestId, profileId)) finish()
                return
            }
        }
        if (intent.action == ACTION_VPN_DISCONNECT) {
            prefs.edit().remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID")
                .remove("VPN_PERMISSION_REQUEST_ID").apply()
            setBooleanPrefValue(false, MvcPreference.HOME_CONNECTOR, prefs)
            send(ACTION_VPN_DISCONNECT); return
        }
        if (intent.action != ACTION_VPN_CONNECT) { finish(); return }
        startConnection()
    }

    private fun startConnection() {
        if (isFinishing || requestId.isNotEmpty()) return
        try {
            if (ConnectionRecovery.visibleActive(prefs)) { finish(); return }
            val activeProfile = kittoku.mvc.profile.ProfileStore(this).ensureInitialized()
            if (activeProfile == null) {
                startActivity(Intent(this, MainActivity::class.java).putExtra(MainActivity.EXTRA_OPEN_PROFILES, true))
                finish()
                return
            }
            PrivacyDisclosure.pendingConnection(this, prefs)?.let {
                PrivacyDisclosureDialog.show(supportFragmentManager, it)
                return
            }
            profileId = activeProfile
            val recover = ConnectionRecovery.plan(prefs, {
                getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == "TUN" && VpnService.prepare(this) != null
            }, getString(R.string.status_disconnected))
            if (recover is RecoveryAction.Resume) {
                try {
                    prefs.edit().putConnectionStatus(ConnectionPhase.CONNECTING, getString(R.string.status_connecting)).apply()
                    startForegroundService(Intent(this, SoftEtherVpnService::class.java).setAction(ACTION_VPN_RECOVER)
                        .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, recover.accepted.sequence))
                } catch (error: Exception) {
                    ConnectionRecovery.recoveryLaunchFailed(prefs, recover.accepted.sequence, getString(R.string.status_disconnected))
                    throw error
                }
                finish(); return
            }
            requestId = java.util.UUID.randomUUID().toString()
            ConnectionRecovery.permissionStarted(prefs, requestId, profileId)
            prefs.edit().putString("QUICK_CONNECT_REQUEST_ID", requestId)
                .putString("VPN_PERMISSION_PROFILE_ID", profileId).putString("VPN_PERMISSION_REQUEST_ID", requestId)
                .putBoolean(MvcPreference.HOME_CONNECTOR.name, true)
                .putConnectionStatus(ConnectionPhase.CONNECTING, getString(R.string.status_connecting)).apply()
            val request = if (getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == "TUN") VpnService.prepare(this) else null
            if (request == null) send(ACTION_VPN_CONNECT) else permission.launch(request)
        } catch (error: Exception) { fail(error) }
    }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("requestId", requestId); outState.putString("profileId", profileId)
        super.onSaveInstanceState(outState)
    }
    private fun send(action: String) {
        var serviceRequest: kittoku.mvc.profile.ProfileConnectionRequest? = null
        if (action == ACTION_VPN_CONNECT) {
            if (!isCurrentRequest()) { finish(); return }
        }
        try {
            val intent = Intent(this, SoftEtherVpnService::class.java).setAction(action)
            if (action == ACTION_VPN_CONNECT) {
                serviceRequest = kittoku.mvc.profile.ProfileConnectionRequest.reserve(prefs, profileId)
                intent.putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_PROFILE, serviceRequest.profileId)
                    .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_NONCE, serviceRequest.nonce)
                    .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, serviceRequest.sequence)
            } else if (action == ACTION_VPN_DISCONNECT) {
                val sequence = kittoku.mvc.profile.ProfileConnectionRequest.reserveStop(prefs)
                intent.putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, sequence)
            }
            if (action == ACTION_VPN_DISCONNECT) startService(intent) else startForegroundService(intent)
            if (prefs.getString("QUICK_CONNECT_REQUEST_ID", "") == requestId) {
                prefs.edit().remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID")
                    .remove("VPN_PERMISSION_REQUEST_ID").apply()
            }
            ConnectionRecovery.permissionFinished(prefs, requestId, profileId)
        } catch (error: Exception) {
            serviceRequest?.let { kittoku.mvc.profile.ProfileConnectionRequest.cancel(prefs, it) }
            fail(error)
        }
        finish()
    }
    private fun fail(error: Exception) {
        if (requestId.isNotEmpty() && prefs.getString("QUICK_CONNECT_REQUEST_ID", "") == requestId) {
            prefs.edit().remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID")
                .remove("VPN_PERMISSION_REQUEST_ID").putBoolean(MvcPreference.HOME_CONNECTOR.name, false)
                .putConnectionStatus(ConnectionPhase.FAILED, getString(R.string.ui_start_failed, error.javaClass.simpleName)).apply()
        }
        ConnectionRecovery.permissionFinished(prefs, requestId, profileId)
        DiagnosticLog.record("ERROR", "QUICK_TILE", error.stackTraceToString())
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    override fun onDestroy() {
        if (isFinishing && ConnectionRecovery.isLocalPermission(prefs, requestId, profileId) &&
            prefs.getString("QUICK_CONNECT_REQUEST_ID", null) == requestId &&
            prefs.getString("VPN_PERMISSION_REQUEST_ID", null) == requestId) {
            prefs.edit().remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID")
                .remove("VPN_PERMISSION_REQUEST_ID").putBoolean("HOME_CONNECTOR", false).apply()
            ConnectionRecovery.permissionFinished(prefs, requestId, profileId)
        }
        super.onDestroy()
    }
}
