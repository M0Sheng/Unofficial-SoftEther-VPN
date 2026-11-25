package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.net.Inet4Address
import java.net.InetAddress

private val ipv4Default = RootBypassCidr.parse("0.0.0.0/0")
private val ipv6Default = RootBypassCidr.parse("::/0")
private val mappedIpv6Parent = RootBypassCidr.parse("::fffe:0:0/95")
private val mappedIpv6Sibling = RootBypassCidr.parse("::fffe:0:0/96")

internal fun parseTapDestinationRules(
    configuration: TunDestinationConfiguration,
    ipv6Enabled: Boolean,
): List<RootBypassRule> {
    if (configuration.mode == TunDestinationMode.ALL) return emptyList()
    val rules = parseRootBypassRules(configuration.activeRules)
    if (configuration.mode == TunDestinationMode.INCLUDE) {
        require(rules.isNotEmpty()) { appText(R.string.route_error_destination_allowlist_empty) }
        require(ipv6Enabled || rules.none { it is RootBypassRule.Network && it.cidr.family == 6 }) {
            appText(R.string.route_error_tap_allowlist_needs_ipv6)
        }
    }
    return rules
}

/** Compile each TAP destination mode into the existing, bounded underlay-bypass plan. */
internal fun planTapDestinationRoutes(
    configuration: TunDestinationConfiguration,
    ipv6Enabled: Boolean,
    resolvedDomains: Map<String, List<InetAddress>> = emptyMap(),
): RootBypassPlan {
    if (configuration.mode == TunDestinationMode.ALL) return RootBypassPlan(emptyList(), emptyList())
    val rules = parseTapDestinationRules(configuration, ipv6Enabled)
    val eligibleAnswers = if (configuration.mode == TunDestinationMode.INCLUDE && !ipv6Enabled) {
        resolvedDomains.mapValues { (_, answers) ->
            require(answers.size <= RootBypassRules.MAX_ADDRESSES_PER_DOMAIN) { appText(R.string.route_error_domain_too_many_addresses) }
            answers.filterIsInstance<Inet4Address>()
        }
    } else resolvedDomains
    val snapshot = RootBypassRules.plan(rules, eligibleAnswers)
    if (configuration.mode == TunDestinationMode.EXCLUDE) return snapshot

    val bypass = mutableListOf<RootBypassCidr>()
    appendComplement(ipv4Default, snapshot.networks.filter { it.family == 4 }, bypass)
    if (ipv6Enabled) appendComplement(ipv6Default, snapshot.networks.filter { it.family == 6 }, bypass)
    return RootBypassPlan(bypass.toList(), snapshot.domains)
}

/** Candidates are normalized descendants of prefix. Split only paths with listed destinations. */
private fun appendComplement(
    prefix: RootBypassCidr,
    included: List<RootBypassCidr>,
    bypass: MutableList<RootBypassCidr>,
) {
    if (included.any { it == prefix }) return
    if (included.isEmpty()) {
        require(bypass.size < RootBypassRules.MAX_PLAN_CIDRS) {
            appText(R.string.route_error_tap_allowlist_limit, RootBypassRules.MAX_PLAN_CIDRS)
        }
        bypass.add(prefix)
        return
    }

    // Mapped IPv6 destinations use the IPv4 socket route. The root helper accepts only native CIDRs.
    if (prefix == mappedIpv6Parent) {
        appendComplement(mappedIpv6Sibling, included, bypass)
        return
    }
    val (left, right) = prefix.split()
    appendComplement(left, included.filter(left::contains), bypass)
    appendComplement(right, included.filter(right::contains), bypass)
}