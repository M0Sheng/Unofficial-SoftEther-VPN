package kittoku.mvc.activity

import android.content.res.Configuration
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import kittoku.mvc.R
import kittoku.mvc.databinding.ActivityThemeSettingsBinding
import kittoku.mvc.ui.AccentColor
import kittoku.mvc.ui.AccentColorDialogFragment
import kittoku.mvc.ui.AccentSettings
import kittoku.mvc.ui.ThemeSettings

class ThemeSettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val binding = ActivityThemeSettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val night = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, binding.root).apply {
            isAppearanceLightStatusBars = !night
            isAppearanceLightNavigationBars = !night
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(binding.root)

        binding.pageHeading.pageToolbar.apply {
            setTitle(R.string.theme_settings_title)
            setNavigationIcon(R.drawable.ui_ic_back)
            setNavigationIconTint(getColor(R.color.ui_text_primary))
            setNavigationOnClickListener { finish() }
        }

        val modes = mapOf(
            R.id.themeModeSystem to ThemeSettings.SYSTEM,
            R.id.themeModeLight to ThemeSettings.LIGHT,
            R.id.themeModeDark to ThemeSettings.DARK
        )
        binding.themeModes.isSaveFromParentEnabled = false
        binding.themeModes.check(modes.entries.first { it.value == ThemeSettings.current(this) }.key)
        binding.themeModes.addOnButtonCheckedListener { _, id, checked ->
            if (checked) modes[id]?.let { ThemeSettings.saveAndApply(this, it) }
        }

        val accent = AccentSettings.current(this)
        binding.themeSystemColors.isSaveFromParentEnabled = false
        binding.themeSystemColors.isChecked = accent == AccentColor.SYSTEM
        binding.themeAccentValue.setText(accent.label)
        binding.themeSystemColors.setOnCheckedChangeListener { _, enabled ->
            if (AccentSettings.setSystemColors(this, enabled)) recreate()
        }
        binding.themeAccent.setOnClickListener {
            val manager = supportFragmentManager
            val tag = AccentColorDialogFragment.TAG
            if (!manager.isStateSaved && manager.findFragmentByTag(tag) == null) {
                AccentColorDialogFragment().showNow(manager, tag)
            }
        }
    }
}
