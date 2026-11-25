package kittoku.mvc

import android.app.Application
import androidx.preference.PreferenceManager
import com.google.android.material.color.ColorContrast
import com.google.android.material.color.ColorContrastOptions
import kittoku.mvc.backend.BackendModeMigration
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.i18n.initializeAppText
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.ui.AccentSettings
import kittoku.mvc.ui.ThemeSettings

/** Apply the persisted theme before the first Activity inflates its views. */
class HomeVpnApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        initializeAppText(this)
        val preferences = PreferenceManager.getDefaultSharedPreferences(this)
        if (preferences.contains(MvcPreference.BACKEND_MODE.name)) {
            runCatching { BackendModeMigration.migrate(this, preferences) }.onFailure { error ->
                DiagnosticLog.record("ERROR", "BACKEND_MIGRATION", error.stackTraceToString())
            }
        }
        runCatching { kittoku.mvc.profile.ProfileStore(this).ensureInitialized() }.onFailure { error ->
            DiagnosticLog.record("ERROR", "PROFILE_MIGRATION", error.stackTraceToString())
        }
        // Refresh the previous version's TAP summary after the observer starts.
        val statusKey = MvcPreference.HOME_STATUS.name
        if (preferences.getString(statusKey, "").orEmpty().contains("\n[系统默认网络]\n")) {
            preferences.edit().remove(statusKey).apply()
        }
        ThemeSettings.applySavedTheme(this)
        AccentSettings.applyToActivities(this)
        // Recompute the chosen dynamic palette when Android's contrast changes.
        ColorContrast.applyToActivitiesIfAvailable(this, ColorContrastOptions.Builder().build())
    }
}
