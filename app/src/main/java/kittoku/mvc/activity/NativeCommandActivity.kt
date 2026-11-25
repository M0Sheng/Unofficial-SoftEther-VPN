package kittoku.mvc.activity

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.graphics.Typeface
import android.view.ViewGroup
import androidx.appcompat.content.res.AppCompatResources
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import android.content.res.Configuration
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kittoku.mvc.nativecore.NativeCoreRunner
import kittoku.mvc.R

/** Local-only official vpncmd console. No commands or credentials are accepted from Intents. */
class NativeCommandActivity : AppCompatActivity() {
    private val main = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = getString(R.string.native_command_title)
        val padding = resources.getDimensionPixelSize(R.dimen.ui_page_inset)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(getColor(R.color.ui_background))
            setPadding(padding, padding, padding, padding)
        }
        val toolbar = MaterialToolbar(this).apply {
            title = getString(R.string.native_command_title)
            isTitleCentered = true
            setNavigationIcon(R.drawable.ui_ic_back)
            setNavigationIconTint(getColor(R.color.ui_text_primary))
            setNavigationContentDescription(androidx.appcompat.R.string.abc_action_bar_up_description)
            setNavigationOnClickListener { finish() }
            inflateMenu(R.menu.routing_help)
            menu.findItem(R.id.routingHelp).setOnMenuItemClickListener {
                showCommandHelp()
                true
            }
        }
        content.addView(toolbar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        val command: EditText = TextInputEditText(this).apply {
            id = android.R.id.edit
            minLines = 3
            maxLines = 8
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            typeface = Typeface.MONOSPACE
            isSaveEnabled = false
            importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val commandField = TextInputLayout(this, null, com.google.android.material.R.attr.textInputOutlinedStyle).apply {
            hint = "AccountList"
            addView(command, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        content.addView(commandField)
        val execute = MaterialButton(this).apply {
            setText(R.string.native_command_execute)
            minimumHeight = (48 * resources.displayMetrics.density).toInt()
        }
        content.addView(execute, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = padding / 2; bottomMargin = padding / 2 })
        val result = TextView(this).apply {
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium)
            setTextColor(AppCompatResources.getColorStateList(context, R.color.ui_text_primary))
            typeface = Typeface.MONOSPACE
            setPadding(padding, padding, padding, padding)
            setTextIsSelectable(true)
        }
        content.addView(ScrollView(this).apply {
            setBackgroundResource(R.drawable.ui_panel_surface)
            addView(result)
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(content)
        val night = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, content).apply {
            isAppearanceLightStatusBars = !night
            isAppearanceLightNavigationBars = !night
        }
        ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(padding + bars.left, bars.top, padding + bars.right, padding + maxOf(bars.bottom, ime.bottom))
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(content)
        execute.setOnClickListener {
            val current = NativeCoreRunner.active
            if (current == null) { result.setText(R.string.native_command_service_unavailable); return@setOnClickListener }
            val text = command.text.toString()
            execute.isEnabled = false
            result.setText(R.string.profile_runtime_command_running)
            Thread({
                val response = runCatching { current.executeAdvanced(text) }
                main.post {
                    if (!isFinishing && !isDestroyed) {
                        execute.isEnabled = true
                        result.text = response.fold(
                            { getString(R.string.profile_runtime_command_result, it.exitCode, it.output) },
                            { it.message ?: it.javaClass.simpleName }
                        )
                    }
                }
            }, "homevpn-native-console").also { it.isDaemon = true; it.start() }
        }
    }

    private fun showCommandHelp() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.native_command_title)
            .setMessage(getString(R.string.profile_runtime_command_help,
                getString(R.string.native_management_only_title), getString(R.string.vpn_virtual_adapter)))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    override fun onDestroy() { main.removeCallbacksAndMessages(null); super.onDestroy() }
}
