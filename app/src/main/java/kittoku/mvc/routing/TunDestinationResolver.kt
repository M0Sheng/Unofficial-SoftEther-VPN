package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.net.Network
import android.os.Looper
import kittoku.mvc.control.DiagnosticLog
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Resolve only on the selected physical network. Never request/activate another network or use global DNS. */
internal fun resolveTunDestinationRoutes(
    configuration: TunDestinationConfiguration,
    network: Network?,
    ipv6Enabled: Boolean,
    sessionId: String,
): TunDestinationRoutes {
    val started = System.nanoTime()
    val result = resolveTunDestinationRules(configuration, ipv6Enabled, checkAvailable = {
        check(Looper.myLooper() != Looper.getMainLooper()) { appText(R.string.route_error_tun_dns_background) }
        val physical = network ?: throw IOException(appText(R.string.route_error_tun_dns_underlay))
        require(physical.networkHandle != 0L) { appText(R.string.route_error_underlay_invalid) }
        // Binding an unconnected socket sends no packets; a stale netId must not resolve through the new default.
        DatagramSocket(null).use { physical.bindSocket(it) }
    }, lookup = { hostname -> checkNotNull(network).getAllByName(hostname).toList() })
    result.domains.forEach { snapshot ->
        DiagnosticLog.record("INFO", "TUN_DESTINATION", "Exact domain snapshot host=${snapshot.hostname} " +
            "addresses=${snapshot.addresses.joinToString { it.canonical }}; shared IPs use the same route; reconnect to refresh", sessionId)
    }
    DiagnosticLog.record("INFO", "TUN_DESTINATION", "Destination mode=${configuration.mode} original_network=$network " +
        "ipv6=$ipv6Enabled ipv4_included=${result.ipv4.included.size} ipv4_excluded=${result.ipv4.excluded.size} " +
        "ipv6_included=${result.ipv6.included.size} ipv6_excluded=${result.ipv6.excluded.size} " +
        "domains=${result.domains.size} elapsed_ms=${(System.nanoTime() - started) / 1_000_000}", sessionId)
    return result
}

/** Injectable boundary for deterministic DNS and detached-network regression tests. */
internal fun resolveTunDestinationRules(
    configuration: TunDestinationConfiguration,
    ipv6Enabled: Boolean,
    checkAvailable: () -> Unit,
    lookup: (String) -> List<InetAddress>,
): TunDestinationRoutes {
    val futures = mutableListOf<Pair<String, Future<List<InetAddress>>>>()
    val started = System.nanoTime()
    try {
        if (configuration.mode == TunDestinationMode.ALL) {
            return planTunDestinationRoutes(configuration, ipv6Enabled)
        }
        val rules = parseRootBypassRules(configuration.activeRules)
        require(ipv6Enabled || rules.none { it is RootBypassRule.Network && it.cidr.family == 6 }) {
            appText(R.string.route_error_destination_needs_ipv6)
        }
        val domains = rules.filterIsInstance<RootBypassRule.Domain>()
        if (domains.isEmpty()) return planTunDestinationRoutes(configuration, ipv6Enabled)
        checkAvailable()
        domains.forEach { rule ->
            futures += rule.hostname to tunDestinationDnsExecutor.submit<List<InetAddress>> {
                lookup(rule.hostname)
            }
        }
        val resolved = linkedMapOf<String, List<InetAddress>>()
        futures.forEach { (hostname, future) ->
            val remaining = TUN_DESTINATION_DNS_TIMEOUT_NANOS - (System.nanoTime() - started)
            if (remaining <= 0L) throw TimeoutException("Destination DNS snapshot deadline exceeded")
            val answers = future.get(remaining, TimeUnit.NANOSECONDS)
            require(answers.size <= RootBypassRules.MAX_ADDRESSES_PER_DOMAIN) { appText(R.string.route_error_hostname_too_many_addresses, hostname) }
            resolved[hostname] = answers
        }
        // A network can disappear while its resolver is returning cached answers.
        checkAvailable()
        return planTunDestinationRoutes(configuration, ipv6Enabled, resolved)
    } catch (error: Exception) {
        val cause = if (error is ExecutionException) error.cause ?: error else error
        if (error is InterruptedException) Thread.currentThread().interrupt()
        throw IOException(appText(R.string.route_error_tun_dns_failed, cause.message ?: cause.javaClass.simpleName), cause)
    } finally {
        futures.forEach { (_, future) -> if (!future.isDone) future.cancel(true) }
        tunDestinationDnsExecutor.purge()
    }
}

private const val TUN_DESTINATION_DNS_TIMEOUT_NANOS = 10_000_000_000L
// Native DNS may ignore interruption. Bounded workers/queue prevent repeated failures growing without limit.
private val tunDestinationDnsExecutor = ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
    { task -> Thread(task, "homevpn-tun-destination-dns").also { it.isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
