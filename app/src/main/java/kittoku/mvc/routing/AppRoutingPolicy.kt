package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText

enum class AppRoutingMode { ALL, INCLUDE, EXCLUDE }

data class AppRoutingConfiguration(val mode: AppRoutingMode, val packages: Set<String>)

data class AppRoutingPlan(
    val mode: AppRoutingMode,
    val allowedPackages: List<String>,
    val disallowedPackages: List<String>,
    val missingPackages: Set<String>,
    val sharedUidPackages: Set<String>,
)

/** Pure policy: Android applies package allow/disallow lists at UID granularity. */
object AppRoutingPolicy {
    fun parseMode(value: String): AppRoutingMode = AppRoutingMode.entries.firstOrNull { it.name == value }
        ?: throw IllegalArgumentException(appText(R.string.route_error_app_mode))

    fun requireSupportedBackend(mode: AppRoutingMode, backend: String) {
        require(backend in setOf("TUN", "ROOT_NATIVE")) { appText(R.string.route_error_backend_invalid) }
    }

    fun selectedUidPackages(selected: Set<String>, installed: Map<String, Int>, ownUid: Int): Set<String> {
        val selectedUids = selected.mapNotNull(installed::get).filter { it != ownUid }.toSet()
        return installed.filterValues { it in selectedUids }.keys
    }

    fun plan(configuration: AppRoutingConfiguration, installed: Map<String, Int>,
             ownPackage: String, ownUid: Int): AppRoutingPlan {
        require(ownPackage.isNotBlank() && ownUid >= 0) { appText(R.string.route_error_vpn_app_uid) }
        require(configuration.packages.all { PACKAGE.matches(it) }) { appText(R.string.route_error_app_package_reselect) }
        if (configuration.mode == AppRoutingMode.ALL) {
            return AppRoutingPlan(configuration.mode, emptyList(), listOf(ownPackage), emptySet(), emptySet())
        }
        val selected = configuration.packages - ownPackage
        val missing = selected - installed.keys
        val effective = selectedUidPackages(selected, installed, ownUid)
        val shared = effective - selected
        return when (configuration.mode) {
            AppRoutingMode.INCLUDE -> {
                require(effective.isNotEmpty()) {
                    appText(R.string.route_error_app_allowlist_empty)
                }
                AppRoutingPlan(configuration.mode, effective.sorted(), emptyList(), missing, shared)
            }
            AppRoutingMode.EXCLUDE -> AppRoutingPlan(configuration.mode, emptyList(),
                (effective + ownPackage).sorted(), missing, shared)
            AppRoutingMode.ALL -> error("Handled above")
        }
    }

    private val PACKAGE = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*")
}
