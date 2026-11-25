package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.net.Inet4Address
import java.net.InetAddress
import java.util.Collections

/** Positive and excluded prefixes for one Android TUN address family. */
internal class TunDestinationFamilyRoutes internal constructor(
    val family: Int,
    included: List<RootBypassCidr>,
    excluded: List<RootBypassCidr>,
) {
    val included: List<RootBypassCidr> = Collections.unmodifiableList(included.toList())
    val excluded: List<RootBypassCidr> = Collections.unmodifiableList(excluded.toList())

    init {
        require(family == 4 || family == 6)
        require(this.included.size <= RootBypassRules.MAX_PLAN_CIDRS && this.excluded.size <= RootBypassRules.MAX_PLAN_CIDRS)
        require(this.included.all { it.family == family } && this.excluded.all { it.family == family })
    }

    val hasRoutes: Boolean = hasSurvivingPrefix(this.included, this.excluded)

    fun captures(address: InetAddress): Boolean = captures(address.address)

    fun captures(address: ByteArray): Boolean =
        included.any { it.containsAddress(address) } && excluded.none { it.containsAddress(address) }

    /** Whether an off-link destination still exists, including after multiple covering exclusions. */
    fun hasRoutesOutside(prefix: RootBypassCidr): Boolean =
        if (prefix.family != family) hasRoutes else hasSurvivingPrefix(included, excluded + prefix)
}

internal class TunDestinationRoutes internal constructor(
    val ipv4: TunDestinationFamilyRoutes,
    val ipv6: TunDestinationFamilyRoutes,
    domains: List<RootDomainSnapshot> = emptyList(),
) {
    // Keep the exact connect-time snapshot available for bounded diagnostics.
    val domains: List<RootDomainSnapshot> = Collections.unmodifiableList(domains.map {
        RootDomainSnapshot(it.hostname, Collections.unmodifiableList(it.addresses.toList()))
    })

    fun captures(address: InetAddress): Boolean = captures(address.address)
    fun captures(address: ByteArray): Boolean = when (address.size) {
        4 -> ipv4.captures(address)
        16 -> ipv6.captures(address)
        else -> false
    }
}

/**
 * Pure destination policy. Android application allow/deny lists remain an independent Builder policy.
 * Exact domains use caller-supplied A/AAAA snapshots; this function never performs DNS or changes a route.
 */
internal fun planTunDestinationRoutes(
    configuration: TunDestinationConfiguration,
    ipv6Enabled: Boolean,
    resolvedDomains: Map<String, List<InetAddress>> = emptyMap(),
): TunDestinationRoutes {
    if (configuration.mode == TunDestinationMode.ALL) {
        // Dormant lists may contain old, unsupported input and must not affect ALL.
        return TunDestinationRoutes(familyRoutes(4, listOf(IPV4_DEFAULT), emptyList()),
            familyRoutes(6, if (ipv6Enabled) listOf(IPV6_DEFAULT) else emptyList(), emptyList()))
    }
    val rules = parseRootBypassRules(configuration.activeRules)
    require(configuration.mode != TunDestinationMode.INCLUDE || rules.isNotEmpty()) { appText(R.string.route_error_include_empty) }
    require(ipv6Enabled || rules.none { it is RootBypassRule.Network && it.cidr.family == 6 }) {
        appText(R.string.route_error_destination_needs_ipv6)
    }
    val eligibleAnswers = if (ipv6Enabled) resolvedDomains else resolvedDomains.mapValues { (_, answers) ->
        // IPv6 being disabled never silently enables it through a DNS answer or exclusion.
        require(answers.size <= RootBypassRules.MAX_ADDRESSES_PER_DOMAIN) { appText(R.string.route_error_domain_too_many_addresses) }
        answers.filterIsInstance<Inet4Address>()
    }
    val snapshot = RootBypassRules.plan(rules, eligibleAnswers)
    if (configuration.mode == TunDestinationMode.INCLUDE) {
        snapshot.networks.forEach { cidr ->
            require(hasSurvivingPrefix(listOf(cidr), unsupportedIncludePrefixes)) {
                appText(R.string.route_error_destination_unsupported, cidr.canonical)
            }
        }
    }
    val v4 = snapshot.networks.filter { it.family == 4 }
    val v6 = snapshot.networks.filter { it.family == 6 }
    val result = when (configuration.mode) {
        TunDestinationMode.INCLUDE -> TunDestinationRoutes(familyRoutes(4, v4, emptyList()),
            familyRoutes(6, v6, emptyList()), snapshot.domains)
        TunDestinationMode.EXCLUDE -> TunDestinationRoutes(familyRoutes(4, listOf(IPV4_DEFAULT), v4),
            familyRoutes(6, if (ipv6Enabled) listOf(IPV6_DEFAULT) else emptyList(), v6), snapshot.domains)
        TunDestinationMode.ALL -> error("ALL was handled before parsing dormant rules")
    }
    require(result.ipv4.hasRoutes || result.ipv6.hasRoutes) { appText(R.string.route_error_destination_no_routes) }
    return result
}

private val IPV4_DEFAULT = RootBypassCidr.parse("0.0.0.0/0")
private val IPV6_DEFAULT = RootBypassCidr.parse("::/0")
private val unsupportedIncludePrefixes = listOf("0.0.0.0/32", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fe80::/10", "ff00::/8").map(RootBypassCidr::parse)

private fun familyRoutes(family: Int, included: List<RootBypassCidr>, excluded: List<RootBypassCidr>): TunDestinationFamilyRoutes {
    val result = TunDestinationFamilyRoutes(family, included, excluded)
    // Android must not receive exclude-only routes that would unintentionally enable an omitted family.
    return if (result.hasRoutes) result else TunDestinationFamilyRoutes(family, emptyList(), emptyList())
}

/**
 * A prefix trie answers only whether at least one address survives. It does not materialize a complement.
 * CIDRs either nest or are disjoint. With <=256 exclusions and <=128 address bits, the input trie is bounded.
 */
private fun hasSurvivingPrefix(included: List<RootBypassCidr>, excluded: List<RootBypassCidr>): Boolean {
    require(included.size <= RootBypassRules.MAX_PLAN_CIDRS)
    require(excluded.size <= RootBypassRules.MAX_PLAN_CIDRS + 1)
    var visits = 0
    val maximumVisits = 2 * (excluded.size + 1) * 129 + included.size + 1
    fun survives(prefix: RootBypassCidr, candidates: List<RootBypassCidr>): Boolean {
        check(++visits <= maximumVisits) { appText(R.string.route_error_destination_prefix_limit) }
        if (candidates.any { it.contains(prefix) }) return false
        val children = candidates.filter { prefix.contains(it) }
        if (children.isEmpty()) return true
        val (left, right) = prefix.split()
        return survives(left, children) || survives(right, children)
    }
    return included.any { survives(it, excluded.filter { block -> block.family == it.family }) }
}
