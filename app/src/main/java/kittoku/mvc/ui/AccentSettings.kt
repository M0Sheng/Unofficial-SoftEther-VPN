package kittoku.mvc.ui

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.annotation.ColorInt
import androidx.annotation.StringRes
import androidx.preference.PreferenceManager
import com.google.android.material.color.DynamicColors
import com.google.android.material.color.DynamicColorsOptions
import kittoku.mvc.R
import java.util.WeakHashMap

internal enum class AccentColor(@StringRes val label: Int, @ColorInt val seed: Int?) {
    SYSTEM(R.string.appearance_accent_system, null),
    BLUE(R.string.appearance_accent_blue, 0xFF3367CB.toInt()),
    TEAL(R.string.appearance_accent_teal, 0xFF00796B.toInt()),
    PURPLE(R.string.appearance_accent_purple, 0xFF7754BA.toInt()),
    ROSE(R.string.appearance_accent_rose, 0xFFBD4966.toInt()),
    AMBER(R.string.appearance_accent_amber, 0xFFA65C00.toInt()),
}

internal object AccentSettings {
    const val PREFERENCE_KEY = "UI_ACCENT_COLOR"
    private const val LAST_PRESET_KEY = "UI_ACCENT_LAST_PRESET"

    fun current(context: Context): AccentColor {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context.applicationContext)
        val saved = prefs.getString(PREFERENCE_KEY, null)
        return AccentColor.entries.firstOrNull { it.name == saved } ?: AccentColor.SYSTEM
    }

    fun setSystemColors(context: Context, enabled: Boolean): Boolean {
        if (enabled) return save(context, AccentColor.SYSTEM)
        val saved = PreferenceManager.getDefaultSharedPreferences(context.applicationContext)
            .getString(LAST_PRESET_KEY, null)
        val preset = AccentColor.entries.firstOrNull { it.seed != null && it.name == saved }
        return save(context, preset ?: AccentColor.BLUE)
    }

    fun save(context: Context, color: AccentColor): Boolean {
        val previous = current(context)
        if (color == previous) return false
        val editor = PreferenceManager.getDefaultSharedPreferences(context.applicationContext)
            .edit().putString(PREFERENCE_KEY, color.name)
        val preset = if (color.seed != null) color else previous
        if (preset.seed != null) editor.putString(LAST_PRESET_KEY, preset.name)
        editor.apply()
        return true
    }

    /** Each Activity reads the accent before inflation, after AppCompat attaches its night-mode context. */
    fun applyToActivities(application: Application) {
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            private val appliedColors = WeakHashMap<Activity, AccentColor>()

            override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
                val accent = current(activity)
                appliedColors[activity] = accent
                val seed = accent.seed
                if (seed == null) {
                    DynamicColors.applyToActivityIfAvailable(activity)
                } else {
                    val options = DynamicColorsOptions.Builder().setContentBasedSource(seed).build()
                    DynamicColors.applyToActivityIfAvailable(activity, options)
                }
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityResumed(activity: Activity) {
                if (!activity.isFinishing && appliedColors[activity] != current(activity)) activity.recreate()
            }
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) {
                appliedColors.remove(activity)
            }
        })
    }
}
