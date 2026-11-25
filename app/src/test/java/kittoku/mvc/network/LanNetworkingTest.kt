package kittoku.mvc.network

import org.junit.Assert.*
import org.junit.Test

class LanNetworkingTest {
    @Test fun normalizesAndDeduplicatesLegacyLanRoutes() {
        assertTrue(parseAdditionalLanRoutes("").isEmpty())
        assertEquals(
            listOf("10.24.0.0/16", "172.20.8.0/24"),
            parseAdditionalLanRoutes("10.24.8.1/16, 172.20.8.0/24\n10.24.0.0/16").map { it.toString() }
        )
    }

    @Test fun malformedAndDefaultLegacyRoutesFailWithoutHostnameResolution() {
        listOf("0.0.0.0/0", "192.168.1.2/33", "256.0.0.1/24", "host/24", "::1/128", "10.0.0.1", "1.2.3/24")
            .forEach { value ->
                assertThrows("Accepted invalid LAN route: $value", IllegalArgumentException::class.java) {
                    parseAdditionalLanRoutes(value)
                }
            }
    }

    @Test fun rejectsZeroAndMulticastHardwareAddresses() {
        assertTrue(isUnicastMac(byteArrayOf(2, 1, 2, 3, 4, 5)))
        assertFalse(isUnicastMac(ByteArray(6)))
        assertFalse(isUnicastMac(byteArrayOf(1, 2, 3, 4, 5, 6)))
    }
}
