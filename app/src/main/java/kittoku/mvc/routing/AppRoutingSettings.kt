package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.content.Context
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Process
import kittoku.mvc.control.DiagnosticLog
import java.io.IOException

/** App-local settings. No firewall, root shell, or system-wide network state is modified. */
class AppRoutingSettings(context: Context) {
    private val application = context.applicationContext
    private val preferences = application.getSharedPreferences("app_routing", Context.MODE_PRIVATE)

    fun load(): AppRoutingConfiguration {
        val mode = preferences.getString("mode", null)?.let(AppRoutingPolicy::parseMode) ?: AppRoutingMode.ALL
        return AppRoutingConfiguration(mode, preferences.getStringSet("selected_packages", null).orEmpty().toSet())
    }

    fun save(configuration: AppRoutingConfiguration) {
        preferences.edit().putString("mode", configuration.mode.name)
            .putStringSet("selected_packages", configuration.packages.toSet()).apply()
    }

    fun showSystemApps() = preferences.getBoolean("show_system_apps", false)
    fun setShowSystemApps(show: Boolean) { preferences.edit().putBoolean("show_system_apps", show).apply() }

    fun requireSupportedBackend(backend: String) = AppRoutingPolicy.requireSupportedBackend(load().mode, backend)

    /** Call on an I/O thread when enumerating package metadata could be expensive. */
    fun preflight(backend: String): AppRoutingPlan? {
        val configuration = load()
        AppRoutingPolicy.requireSupportedBackend(configuration.mode, backend)
        if (backend != "TUN") return null
        val ownPackage = application.packageName
        val ownUid = Process.myUid()
        val installed = if (configuration.mode == AppRoutingMode.ALL) mapOf(ownPackage to ownUid)
        else application.packageManager.getInstalledApplications(0).associate { it.packageName to it.uid } + (ownPackage to ownUid)
        return AppRoutingPolicy.plan(configuration, installed, ownPackage, ownUid)
    }

    internal fun applyTo(builder: VpnService.Builder, sessionId: String): AppRoutingPlan {
        val plan = checkNotNull(preflight("TUN"))
        try {
            plan.allowedPackages.forEach(builder::addAllowedApplication)
            plan.disallowedPackages.forEach(builder::addDisallowedApplication)
        } catch (error: PackageManager.NameNotFoundException) {
            // Never establish after an INCLUDE list became empty or partly invalid
            // while PackageManager and Builder observed different install states.
            throw IOException(appText(R.string.route_error_app_unavailable), error)
        }
        DiagnosticLog.record("INFO", "APP_ROUTING", "Configured TUN builder application policy mode=${plan.mode} " +
            "allowed=${plan.allowedPackages.size} disallowed=${plan.disallowedPackages.size} " +
            "missing=${plan.missingPackages.size} shared_uid_expansion=${plan.sharedUidPackages.size}; " +
            "VPN owner UID excluded; effective IP routes still follow selected FULL/LAN mode", sessionId)
        if (plan.missingPackages.isNotEmpty()) DiagnosticLog.record("WARN", "APP_ROUTING",
            "Selected applications no longer installed/visible count=${plan.missingPackages.size}; " +
                "an empty INCLUDE selection is rejected before establish", sessionId)
        return plan
    }
}
