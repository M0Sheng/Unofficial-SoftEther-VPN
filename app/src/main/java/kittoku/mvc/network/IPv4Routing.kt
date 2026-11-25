package kittoku.mvc.network

private const val IPV4_MAX = 0xffff_ffffL

internal fun ipv4Address(bytes: ByteArray): Long {
    require(bytes.size >= 4)
    return (0 until 4).fold(0L) { value, index ->
        (value shl 8) or (bytes[index].toLong() and 0xff)
    }
}

internal fun ipv4Bytes(address: Long): ByteArray {
    require(address in 0..IPV4_MAX)
    return ByteArray(4) { index -> (address ushr (24 - index * 8)).toByte() }
}

internal fun formatIPv4(address: Long): String =
    (0 until 4).joinToString(".") { ((address ushr (24 - it * 8)) and 0xff).toString() }

internal fun parseIPv4(value: String): Long {
    val parts = value.split('.')
    require(parts.size == 4) { "Invalid IPv4 address: $value" }
    return parts.fold(0L) { result, part ->
        require(part.isNotEmpty() && part.all { it in '0'..'9' }) { "Invalid IPv4 address: $value" }
        val octet = part.toIntOrNull()
        require(octet != null && octet in 0..255) { "Invalid IPv4 address: $value" }
        (result shl 8) or octet.toLong()
    }
}

internal data class IPv4Cidr private constructor(val network: Long, val prefix: Int) {
    private val mask: Long = if (prefix == 0) 0 else (IPV4_MAX shl (32 - prefix)) and IPV4_MAX
    val broadcast: Long get() = network or (mask xor IPV4_MAX)

    fun contains(address: Long): Boolean = (address and mask) == network
    fun isBroadcast(address: Long): Boolean = prefix < 31 && address == broadcast
    override fun toString(): String = "${formatIPv4(network)}/$prefix"

    companion object {
        fun of(address: Long, prefix: Int): IPv4Cidr {
            require(prefix in 0..32) { "Invalid IPv4 prefix length: $prefix" }
            val mask = if (prefix == 0) 0 else (IPV4_MAX shl (32 - prefix)) and IPV4_MAX
            return IPv4Cidr(address and mask, prefix)
        }

        fun parse(text: String): IPv4Cidr {
            val parts = text.split('/')
            require(parts.size == 2 && parts[1].isNotEmpty() && parts[1].all { it in '0'..'9' }) {
                "Enter IPv4 networks as address/prefix: $text"
            }
            val prefix = parts[1].toIntOrNull()
            require(prefix != null && prefix in 1..32) { "LAN routes require a prefix from 1 to 32: $text" }
            return of(parseIPv4(parts[0]), prefix)
        }
    }
}

/** Empty preferences mean the DHCP subnet; configured CIDRs add routed LANs. */
internal fun parseAdditionalLanRoutes(value: String): List<IPv4Cidr> = value.trim().split(Regex("[,\\s]+"))
    .filter { it.isNotEmpty() }.map(IPv4Cidr::parse).distinct()

internal fun isUnicastIPv4(address: Long): Boolean {
    val first = (address ushr 24).toInt()
    return address in 1L until IPV4_MAX && first in 1..223 && first != 127
}

