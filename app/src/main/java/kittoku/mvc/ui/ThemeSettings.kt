package kittoku.mvc.ui

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.preference.PreferenceManager

/** One application-wide appearance choice, shared with the preference UI. */
object ThemeSettings {
    const val PREFERENCE_KEY = "UI_THEME"
    const val SYSTEM = "SYSTEM"
    const val LIGHT = "LIGHT"
    const val DARK = "DARK"

    fun current(context: Context): String {
        val saved = PreferenceManager.getDefaultSharedPreferences(context.applicationContext)
            .getString(PREFERENCE_KEY, SYSTEM)
        return if (saved == LIGHT || saved == DARK) saved else SYSTEM
    }

    fun applySavedTheme(context: Context) {
        applyMode(current(context))
    }

    fun saveAndApply(context: Context, mode: String): Boolean {
        if (mode != SYSTEM && mode != LIGHT && mode != DARK) return false
        PreferenceManager.getDefaultSharedPreferences(context.applicationContext)
            .edit().putString(PREFERENCE_KEY, mode).apply()
        applyMode(mode)
        return true
    }

    private fun applyMode(mode: String) {
        val nightMode = when (mode) {
            LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
            DARK -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        }
        if (AppCompatDelegate.getDefaultNightMode() != nightMode) {
            AppCompatDelegate.setDefaultNightMode(nightMode)
        }
    }
}
