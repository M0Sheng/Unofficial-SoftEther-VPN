package kittoku.mvc.preference.custom

import android.content.Context
import android.content.Intent
import android.util.AttributeSet
import androidx.preference.Preference
import kittoku.mvc.R
import kittoku.mvc.activity.DestinationRoutingActivity
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationSettings

internal class DestinationRoutingPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs) {
    override fun onAttached() {
        super.onAttached()
        title = context.getString(R.string.destination_routing_title)
        isSingleLineTitle = false
        refresh()
        intent = Intent(context, DestinationRoutingActivity::class.java)
    }

    fun refresh() {
        val prefs = sharedPreferences ?: return
        summary = runCatching {
            val tap = getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == BackendModePolicy.ROOT_NATIVE
            val mode = if (!prefs.contains(ProfileStore.ACTIVE_ID_KEY)) TunDestinationMode.ALL
                else TunDestinationSettings.effective(context, prefs, tap)?.mode
            val label = when (mode) {
                TunDestinationMode.EXCLUDE -> R.string.destination_mode_exclude
                TunDestinationMode.INCLUDE -> R.string.destination_mode_include
                TunDestinationMode.ALL -> R.string.destination_mode_all
                null -> return@runCatching context.getString(R.string.destination_routing_summary_legacy)
            }
            context.getString(R.string.destination_routing_summary_mode, context.getString(label))
        }.getOrElse { context.getString(R.string.destination_routing_invalid) }
    }
}
