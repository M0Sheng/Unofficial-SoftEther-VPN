package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.content.Context
import android.net.Network
import android.os.Looper
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.profile.ProfileStore
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Resolves address rules on the physical network and reads migration data for older TAP profiles. */
internal class RootBypassSettings(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("routing_bypass", Context.MODE_PRIVATE)

    fun rawText(): String = preferences.getString("rules", "").orEmpty()

    /** Missing mode is a read-only fallback, never an implicit migration. */
    fun loadLegacyConfiguration(): TunDestinationConfiguration = synchronized(ProfileStore.LOCK) {
        if (!preferences.contains(MODE_KEY)) {
            val rules = rawText()
            val mode = if (rules.isBlank()) TunDestinationMode.ALL else TunDestinationMode.EXCLUDE
            return@synchronized TunDestinationConfiguration(mode, "", rules)
        }
        val mode = TunDestinationMode.entries.firstOrNull { it.name == preferences.getString(MODE_KEY, null) }
            ?: throw IllegalArgumentException(appText(R.string.route_error_tap_destination_mode))
        TunDestinationConfiguration(mode, preferences.getString(INCLUDE_KEY, "").orEmpty(),
            preferences.getString(EXCLUDE_KEY, "").orEmpty())
    }

    /** Resolve an immutable connection snapshot on its original Network, before activating TAP. */
    fun resolveForRoot(network: Network, sessionId: String,
                       configuration: TunDestinationConfiguration, ipv6Enabled: Boolean): RootBypassPlan {
        // ALL ignores both retained lists and never starts a resolver task.
        if (configuration.mode == TunDestinationMode.ALL) {
            return planTapDestinationRoutes(configuration, ipv6Enabled)
        }
        val rules = parseTapDestinationRules(configuration, ipv6Enabled)
        val domains = rules.filterIsInstance<RootBypassRule.Domain>()
        if (domains.isEmpty()) return planTapDestinationRoutes(configuration, ipv6Enabled)
        check(Looper.myLooper() != Looper.getMainLooper()) { appText(R.string.route_error_tap_dns_background) }
        require(network.networkHandle != 0L) { appText(R.string.route_error_tap_dns_underlay) }
        val started = System.nanoTime()
        val futures = mutableListOf<Pair<String, Future<Array<InetAddress>>>>()
        try {
            domains.forEach { rule ->
                futures += rule.hostname to resolver.submit<Array<InetAddress>> {
                    // Never fall back to the system default; eth9 may become it during connection.
                    network.getAllByName(rule.hostname)
                }
            }
            val resolved = linkedMapOf<String, List<InetAddress>>()
            futures.forEach { (hostname, future) ->
                val remaining = TOTAL_TIMEOUT_NANOS - (System.nanoTime() - started)
                if (remaining <= 0L) throw java.util.concurrent.TimeoutException("DNS bypass snapshot deadline exceeded")
                val answers = future.get(remaining, TimeUnit.NANOSECONDS)
                require(answers.size <= RootBypassRules.MAX_ADDRESSES_PER_DOMAIN) { appText(R.string.route_error_hostname_too_many_addresses, hostname) }
                resolved[hostname] = answers.toList()
            }
            return planTapDestinationRoutes(configuration, ipv6Enabled, resolved).also { plan ->
                plan.domains.forEach { snapshot ->
                    DiagnosticLog.record("INFO", "ROOT_ROUTE_BYPASS", "Exact domain snapshot mode=${configuration.mode} host=${snapshot.hostname} " +
                        "addresses=${snapshot.addresses.joinToString { it.canonical }}; shared IPs follow the same address policy; refresh requires reconnect", sessionId)
                }
                DiagnosticLog.record("INFO", "ROOT_ROUTE_BYPASS", "Resolved mode=${configuration.mode} IPv6=$ipv6Enabled on original network=$network domains=${plan.domains.size} " +
                    "cidrs=${plan.networks.size} elapsed_ms=${(System.nanoTime() - started) / 1_000_000}; no route rules installed by planner", sessionId)
            }
        } catch (error: Exception) {
            val cause = if (error is java.util.concurrent.ExecutionException) error.cause ?: error else error
            if (error is InterruptedException) Thread.currentThread().interrupt()
            throw IOException(appText(R.string.route_error_tap_destination_snapshot, cause.message ?: cause.javaClass.simpleName), cause)
        } finally {
            futures.forEach { (_, future) -> if (!future.isDone) future.cancel(true) }
            resolver.purge()
        }
    }

    companion object {
        const val MODE_KEY = "ROOT_DESTINATION_MODE"
        const val INCLUDE_KEY = "ROOT_DESTINATION_INCLUDE"
        const val EXCLUDE_KEY = "ROOT_DESTINATION_EXCLUDE"
        private const val TOTAL_TIMEOUT_NANOS = 10_000_000_000L
        // Native resolver calls may ignore interruption; the fixed pool and queue still
        // bound resource use, and each connection fails closed at the shared deadline.
        private val resolver = ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
            { task -> Thread(task, "homevpn-root-bypass-dns").also { it.isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    }
}
