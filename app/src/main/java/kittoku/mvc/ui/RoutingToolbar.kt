package kittoku.mvc.ui

import androidx.annotation.StringRes
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.R

internal fun MaterialToolbar.configureRoutingToolbar(
    @StringRes title: Int,
    @StringRes help: Int,
    onNavigateUp: () -> Unit,
) {
    setTitle(title)
    setNavigationIcon(R.drawable.ui_ic_back)
    setNavigationIconTint(MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurface))
    setNavigationOnClickListener { onNavigateUp() }

    inflateMenu(R.menu.routing_help)
    menu.findItem(R.id.routingHelp).setOnMenuItemClickListener {
        MaterialAlertDialogBuilder(context)
            .setTitle(R.string.routing_help)
            .setMessage(help)
            .setPositiveButton(android.R.string.ok, null)
            .show()
        true
    }
}
