package kittoku.mvc.network

internal fun isUnicastMac(mac: ByteArray): Boolean =
    mac.size == 6 && (mac[0].toInt() and 1) == 0 && mac.any { it.toInt() != 0 }
