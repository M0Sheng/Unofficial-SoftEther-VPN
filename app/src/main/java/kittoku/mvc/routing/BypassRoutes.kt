package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.network.IPv4Cidr
import kittoku.mvc.network.parseIPv4
import java.net.IDN
import java.util.Locale

internal sealed class BypassRule {
    data class Network(val cidr: IPv4Cidr) : BypassRule()
    data class Domain(val hostname: String) : BypassRule()
}

/** Exact domains are snapshots resolved at connect time, never a wildcard/domain proxy engine. */
internal fun parseBypassRules(text: String): List<BypassRule> {
    require(text.length <= 16_384) { appText(R.string.route_error_legacy_bypass_text_limit) }
    val tokens = text.trim().split(Regex("[,;\\s]+")).filter(String::isNotEmpty)
    require(tokens.size <= 128) { appText(R.string.route_error_legacy_bypass_rule_limit) }
    val rules = tokens.map { token ->
        when {
            '/' in token -> {
                val parts = token.split('/')
                require(parts.size == 2 && parts[1].all { it in '0'..'9' } && parts[1].isNotEmpty()) {
                    appText(R.string.route_error_legacy_ipv4_subnet, token)
                }
                val prefix = parts[1].toIntOrNull()
                require(prefix != null && prefix in 0..32) { appText(R.string.route_error_legacy_prefix_range, token) }
                BypassRule.Network(IPv4Cidr.of(parseIPv4(parts[0]), prefix))
            }
            token.all { it in '0'..'9' || it == '.' } -> BypassRule.Network(IPv4Cidr.of(parseIPv4(token), 32))
            else -> {
                require(token.none { it in "*?:/@[]\\#" }) { appText(R.string.route_error_legacy_bypass_rule_type, token) }
                val hostname = runCatching { IDN.toASCII(token.removeSuffix("."), IDN.USE_STD3_ASCII_RULES) }
                    .getOrElse { throw IllegalArgumentException(appText(R.string.route_error_invalid_bypass_hostname, token), it) }.lowercase(Locale.ROOT)
                require(hostname.isNotEmpty() && hostname.length <= 253 && hostname.split('.').all { label ->
                    label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                        label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
                }) { appText(R.string.route_error_invalid_bypass_hostname, token) }
                BypassRule.Domain(hostname)
            }
        }
    }.distinct()
    require(rules.count { it is BypassRule.Domain } <= 16) { appText(R.string.route_error_legacy_bypass_domain_limit) }
    return rules
}
