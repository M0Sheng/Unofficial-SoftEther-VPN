package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import android.content.Context
import android.net.Network
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.network.IPv4Cidr
import kittoku.mvc.network.ipv4Address
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal class RoutingBypassSettings(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("routing_bypass", Context.MODE_PRIVATE)
    fun rawText(): String = preferences.getString("rules", "").orEmpty()
    fun validate() { parseBypassRules(rawText()) }

    /** The resolver is bound to the original underlay, before establishing the TUN. */
    fun resolveForTun(network: Network, sessionId: String): List<IPv4Cidr> {
        val rules = parseBypassRules(rawText())
        val resolved = rules.filterIsInstance<BypassRule.Network>().map { it.cidr }.toMutableList()
        val domains = rules.filterIsInstance<BypassRule.Domain>()
        if (domains.isEmpty()) return resolved.distinct()
        val started = System.nanoTime()
        val futures = mutableListOf<Pair<BypassRule.Domain, Future<Array<InetAddress>>>>()
        try {
            domains.forEach { rule ->
                futures += rule to resolver.submit<Array<InetAddress>> {
                    network.getAllByName(rule.hostname)
                }
            }
            futures.forEach { (rule, future) ->
                val remaining = 10_000_000_000L - (System.nanoTime() - started)
                if (remaining <= 0) throw java.util.concurrent.TimeoutException("DNS bypass resolution timeout")
                val addresses = future.get(remaining, TimeUnit.NANOSECONDS).filterIsInstance<Inet4Address>()
                require(addresses.isNotEmpty()) { appText(R.string.route_error_legacy_dns_no_ipv4, rule.hostname) }
                require(addresses.size <= 64) { appText(R.string.route_error_legacy_dns_many_ipv4, rule.hostname) }
                resolved += addresses.map { IPv4Cidr.of(ipv4Address(it.address), 32) }
                DiagnosticLog.record("INFO", "ROUTE_BYPASS", "Exact domain snapshot host=${rule.hostname} " +
                    "IPv4=${addresses.joinToString { it.hostAddress.orEmpty() }}; shared IPs bypass together; refresh requires reconnect", sessionId)
            }
        } catch (error: Throwable) {
            val cause = if (error is java.util.concurrent.ExecutionException) error.cause ?: error else error
            throw IOException(appText(R.string.route_error_legacy_dns_failed, cause.message ?: cause.javaClass.simpleName), cause)
        } finally {
            futures.forEach { (_, future) -> if (!future.isDone) future.cancel(true) }
        }
        val networks = resolved.distinct()
        DiagnosticLog.record("INFO", "ROUTE_BYPASS", "Bypass snapshot domains=${domains.size} " +
            "networks=${networks.size} elapsed_ms=${(System.nanoTime() - started) / 1_000_000}", sessionId)
        return networks
    }

    private companion object {
        val resolver = ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32),
            { task -> Thread(task, "home-vpn-bypass-dns").also { it.isDaemon = true } }, ThreadPoolExecutor.AbortPolicy())
    }
}
