package kittoku.mvc.routing

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.net.IDN
import java.net.InetAddress
import java.util.Locale

/** Immutable, strictly numeric CIDR suitable for the session route owner, never a shell expression. */
internal class RootBypassCidr private constructor(private val bytes: ByteArray, val prefixLength: Int) {
    val family: Int = if (bytes.size == 4) 4 else 6
    val networkAddress: String = if (family == 4) bytes.joinToString(".") { (it.toInt() and 255).toString() } else formatIpv6(bytes)
    val canonical: String = "$networkAddress/$prefixLength"

    fun contains(other: RootBypassCidr): Boolean {
        if (family != other.family || prefixLength > other.prefixLength) return false
        for (index in bytes.indices) {
            val count = (prefixLength - index * 8).coerceIn(0, 8)
            val mask = (0xff shl (8 - count)) and 255
            if ((bytes[index].toInt() and mask) != (other.bytes[index].toInt() and mask)) return false
        }
        return true
    }

    /** Numeric packet lookup without allocating a host CIDR or formatting an address. */
    fun containsAddress(address: ByteArray): Boolean {
        if (address.size != bytes.size) return false
        for (index in bytes.indices) {
            val count = (prefixLength - index * 8).coerceIn(0, 8)
            val mask = (0xff shl (8 - count)) and 255
            if ((bytes[index].toInt() and mask) != (address[index].toInt() and mask)) return false
        }
        return true
    }

    fun addressBytes(): ByteArray = bytes.copyOf()
    fun toInetAddress(): InetAddress = InetAddress.getByAddress(bytes)

    /** Splits a prefix for bounded routing calculations, without enumerating IP addresses. */
    internal fun split(): Pair<RootBypassCidr, RootBypassCidr> {
        require(prefixLength < bytes.size * 8) { appText(R.string.route_error_cannot_split_host) }
        val right = bytes.copyOf()
        val index = prefixLength / 8
        right[index] = (right[index].toInt() or (1 shl (7 - prefixLength % 8))).toByte()
        return of(bytes, prefixLength + 1) to of(right, prefixLength + 1)
    }

    override fun toString(): String = canonical
    override fun equals(other: Any?): Boolean = other is RootBypassCidr && canonical == other.canonical
    override fun hashCode(): Int = canonical.hashCode()

    companion object {
        fun parse(text: String): RootBypassCidr {
            require(text.isNotEmpty() && text.none { it.isWhitespace() }) { appText(R.string.route_error_bypass_address_format, text) }
            val parts = text.split('/')
            require(parts.size in 1..2) { appText(R.string.route_error_bypass_subnet_format, text) }
            var address = parts[0]
            if (address.startsWith('[')) {
                require(address.endsWith(']')) { appText(R.string.route_error_ipv6_brackets, text) }
                address = address.substring(1, address.length - 1)
                require(':' in address) { appText(R.string.route_error_brackets_ipv6_only, text) }
            }
            val bytes = if (':' in address) parseIpv6(address) else parseIpv4(address)
            val maximum = bytes.size * 8
            val prefix = if (parts.size == 1) maximum else {
                require(parts[1].isNotEmpty() && parts[1].all { it in '0'..'9' }) { appText(R.string.route_error_bypass_prefix_format, text) }
                parts[1].toIntOrNull()?.takeIf { it in 0..maximum }
                    ?: throw IllegalArgumentException(appText(R.string.route_error_prefix_family_limit, if (bytes.size == 4) 4 else 6, maximum, text))
            }
            return of(bytes, prefix)
        }

        fun host(address: InetAddress): RootBypassCidr = of(address.address, address.address.size * 8)

        private fun of(address: ByteArray, prefix: Int): RootBypassCidr {
            require(address.size == 4 || address.size == 16) { appText(R.string.route_error_address_family) }
            require(prefix in 0..address.size * 8)
            if (address.size == 16) {
                require(!(address.take(10).all { it == 0.toByte() } && address[10] == 0xff.toByte() && address[11] == 0xff.toByte())) {
                    appText(R.string.route_error_ipv4_mapped)
                }
            }
            val masked = address.copyOf()
            for (index in masked.indices) {
                val count = (prefix - index * 8).coerceIn(0, 8)
                val mask = (0xff shl (8 - count)) and 255
                masked[index] = (masked[index].toInt() and mask).toByte()
            }
            return RootBypassCidr(masked, prefix)
        }

        private fun parseIpv4(address: String): ByteArray {
            val parts = address.split('.')
            require(parts.size == 4) { appText(R.string.route_error_ipv4_octets, address) }
            return parts.map { part ->
                require(part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' } &&
                    (part.length == 1 || part[0] != '0')) { appText(R.string.route_error_invalid_ipv4, address) }
                val value = part.toIntOrNull()
                require(value != null && value in 0..255) { appText(R.string.route_error_ipv4_range, address) }
                value.toByte()
            }.toByteArray()
        }

        /** Numeric parsing only: never invoke a resolver while validating user input. */
        private fun parseIpv6(input: String): ByteArray {
            require(input.isNotEmpty() && input.none { it in "%[]/" } &&
                input.all { it in '0'..'9' || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }) {
                appText(R.string.route_error_ipv6_format, input)
            }
            var address = input
            if ('.' in address) {
                val separator = address.lastIndexOf(':')
                require(separator >= 0) { appText(R.string.route_error_ipv6_embedded_ipv4, input) }
                val ipv4 = parseIpv4(address.substring(separator + 1))
                val first = ((ipv4[0].toInt() and 255) shl 8) or (ipv4[1].toInt() and 255)
                val second = ((ipv4[2].toInt() and 255) shl 8) or (ipv4[3].toInt() and 255)
                address = address.substring(0, separator + 1) + first.toString(16) + ":" + second.toString(16)
            }
            val compressed = address.indexOf("::")
            require(compressed == address.lastIndexOf("::")) { appText(R.string.route_error_ipv6_multiple_compressions, input) }
            fun groups(part: String): List<Int> = if (part.isEmpty()) emptyList() else part.split(':').map { group ->
                require(group.length in 1..4 && group.all { it.digitToIntOrNull(16) != null }) { appText(R.string.route_error_ipv6_group, input) }
                group.toInt(16)
            }
            val expanded = if (compressed < 0) {
                groups(address).also { require(it.size == 8) { appText(R.string.route_error_ipv6_groups, input) } }
            } else {
                val left = groups(address.substring(0, compressed))
                val right = groups(address.substring(compressed + 2))
                require(left.size + right.size < 8) { appText(R.string.route_error_ipv6_empty_compression, input) }
                left + List(8 - left.size - right.size) { 0 } + right
            }
            return ByteArray(16) { index -> if (index % 2 == 0) (expanded[index / 2] ushr 8).toByte() else expanded[index / 2].toByte() }
        }

        private fun formatIpv6(bytes: ByteArray): String {
            val groups = IntArray(8) { index -> ((bytes[index * 2].toInt() and 255) shl 8) or (bytes[index * 2 + 1].toInt() and 255) }
            var bestStart = -1
            var bestLength = 1
            var index = 0
            while (index < groups.size) {
                if (groups[index] != 0) { index++; continue }
                val start = index
                while (index < groups.size && groups[index] == 0) index++
                if (index - start > bestLength) { bestStart = start; bestLength = index - start }
            }
            if (bestStart < 0) return groups.joinToString(":") { it.toString(16) }
            val left = groups.take(bestStart).joinToString(":") { it.toString(16) }
            val right = groups.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
            return "$left::$right"
        }
    }
}

internal sealed class RootBypassRule {
    data class Network(val cidr: RootBypassCidr) : RootBypassRule()
    data class Domain(val hostname: String) : RootBypassRule()
}

internal data class RootDomainSnapshot(val hostname: String, val addresses: List<RootBypassCidr>)
internal data class RootBypassPlan(val networks: List<RootBypassCidr>, val domains: List<RootDomainSnapshot>) {
    val cidrs: List<String> get() = networks.map { it.canonical }
}

internal fun parseRootBypassRules(text: String): List<RootBypassRule> = RootBypassRules.parse(text)

internal object RootBypassRules {
    const val MAX_TEXT_LENGTH = 16_384
    const val MAX_RULES = 128
    const val MAX_DOMAINS = 16
    const val MAX_ADDRESSES_PER_DOMAIN = 64
    const val MAX_PLAN_CIDRS = 256

    fun parse(text: String): List<RootBypassRule> {
        require(text.length <= MAX_TEXT_LENGTH) { appText(R.string.route_error_bypass_text_limit, MAX_TEXT_LENGTH) }
        val tokens = text.trim().split(Regex("[,;\\s]+")).filter { it.isNotEmpty() }
        require(tokens.size <= MAX_RULES) { appText(R.string.route_error_bypass_rule_limit, MAX_RULES) }
        val rules = tokens.map { token ->
            val legacyNumeric = token.split('.').all { part ->
                part.all { it in '0'..'9' } || (part.startsWith("0x", ignoreCase = true) && part.drop(2).all { it.digitToIntOrNull(16) != null })
            }
            if ('/' in token || ':' in token || token.startsWith('[') || legacyNumeric) {
                RootBypassRule.Network(RootBypassCidr.parse(token))
            } else {
                require(token.none { it in "*?:/@[]\\#\u0000" }) { appText(R.string.route_error_destination_rule_type, token) }
                val hostname = runCatching { IDN.toASCII(token, IDN.USE_STD3_ASCII_RULES) }
                    .getOrElse { throw IllegalArgumentException(appText(R.string.route_error_invalid_bypass_hostname, token), it) }.removeSuffix(".").lowercase(Locale.ROOT)
                require(hostname.length in 1..253 && hostname.split('.').all { label ->
                    label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                        label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
                }) { appText(R.string.route_error_invalid_bypass_hostname, token) }
                if (hostname.all { it in '0'..'9' || it == '.' }) RootBypassRule.Network(RootBypassCidr.parse(hostname))
                else RootBypassRule.Domain(hostname)
            }
        }.distinct()
        require(rules.count { it is RootBypassRule.Domain } <= MAX_DOMAINS) { appText(R.string.route_error_domain_count, MAX_DOMAINS) }
        return rules
    }

    /** DNS inputs are explicitly supplied; this pure planner never resolves names itself. */
    fun plan(rules: List<RootBypassRule>, resolved: Map<String, List<InetAddress>> = emptyMap()): RootBypassPlan {
        require(rules.size <= MAX_RULES)
        val domains = rules.filterIsInstance<RootBypassRule.Domain>().distinct()
        require(domains.size <= MAX_DOMAINS)
        val snapshots = domains.map { rule ->
            val answers = resolved[rule.hostname] ?: throw IllegalArgumentException(appText(R.string.route_error_missing_dns_snapshot, rule.hostname))
            require(answers.size <= MAX_ADDRESSES_PER_DOMAIN) { appText(R.string.route_error_domain_limit_addresses, MAX_ADDRESSES_PER_DOMAIN, rule.hostname) }
            val addresses = answers.filterNot { it.isAnyLocalAddress || it.isLoopbackAddress || it.isMulticastAddress || it.isLinkLocalAddress }
                .filter { it.address.size != 4 || (it.address[0].toInt() and 255) in 1..223 }
                .map(RootBypassCidr::host).distinct().sortedBy { it.canonical }
            require(addresses.isNotEmpty()) { appText(R.string.route_error_domain_no_unicast, rule.hostname) }
            RootDomainSnapshot(rule.hostname, addresses)
        }
        val combined = rules.filterIsInstance<RootBypassRule.Network>().map { it.cidr } + snapshots.flatMap { it.addresses }
        val normalized = mutableListOf<RootBypassCidr>()
        combined.distinct().sortedWith(compareBy<RootBypassCidr> { it.family }.thenBy { it.prefixLength }.thenBy { it.networkAddress })
            .forEach { cidr ->
                if (normalized.none { it.contains(cidr) }) normalized.add(cidr)
                require(normalized.size <= MAX_PLAN_CIDRS) { appText(R.string.route_error_bypass_snapshot_limit, MAX_PLAN_CIDRS) }
            }
        return RootBypassPlan(normalized.toList(), snapshots)
    }
}
