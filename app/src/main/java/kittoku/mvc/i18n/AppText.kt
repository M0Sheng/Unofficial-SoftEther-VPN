package kittoku.mvc.i18n

import android.content.Context
import androidx.annotation.StringRes

@Volatile
private var appContext: Context? = null

internal fun initializeAppText(context: Context) {
    appContext = context.applicationContext
}

internal fun appLocaleTags(): String? = appContext?.resources?.configuration?.locales?.toLanguageTags()

/** Resolves messages from context-free session and validation code using the current app locale. */
internal fun appText(@StringRes id: Int, vararg arguments: Any): String {
    val context = appContext ?: return buildString {
        // Local JVM tests don't create the Android application or load app resources.
        append("Android string 0x").append(id.toString(16))
        if (arguments.isNotEmpty()) arguments.joinTo(this, prefix = " (", postfix = ")")
    }
    return if (arguments.isEmpty()) context.getString(id) else context.getString(id, *arguments)
}
