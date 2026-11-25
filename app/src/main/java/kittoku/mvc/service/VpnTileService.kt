package kittoku.mvc.service

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.res.Configuration
import android.graphics.drawable.Icon
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.activity.QuickConnectActivity
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getBooleanPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.ConnectionRecovery

class VpnTileService : TileService() {
    private val prefs by lazy { PreferenceManager.getDefaultSharedPreferences(this) }
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> updateTile() }
    override fun onStartListening() { super.onStartListening(); prefs.registerOnSharedPreferenceChangeListener(listener); updateTile() }
    override fun onStopListening() { prefs.unregisterOnSharedPreferenceChangeListener(listener); super.onStopListening() }
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        unlockAndRun {
            val action = if (ConnectionRecovery.visibleActive(prefs)) ACTION_VPN_DISCONNECT else ACTION_VPN_CONNECT
            val intent = Intent(this, QuickConnectActivity::class.java).setAction(action)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivityAndCollapse(PendingIntent.getActivity(this, 10, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
        }
    }
    private fun updateTile() {
        val tile = qsTile ?: return
        val enabled = ConnectionRecovery.visibleActive(prefs)
        tile.state = if (enabled) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name_short)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_lan_bridge_mono)
        val status = if (enabled) getStringPrefValue(MvcPreference.HOME_STATUS, prefs).lineSequence().firstOrNull().orEmpty()
            else getString(R.string.status_disconnected)
        tile.contentDescription = getString(R.string.network_runtime_vpn_tile_description, getString(R.string.app_name_short), status)
        tile.subtitle = status.ifBlank { getString(R.string.status_disconnected) }
        tile.updateTile()
    }
    companion object {
        fun refresh(context: Context) {
            runCatching { requestListeningState(context, ComponentName(context, VpnTileService::class.java)) }
                .onFailure { DiagnosticLog.record("DEBUG", "QUICK_TILE", context.getString(R.string.network_runtime_log_quick_tile_refresh_error, it.javaClass.simpleName)) }
        }
    }
}
