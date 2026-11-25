package kittoku.mvc.routing

import kittoku.mvc.network.IPv4Cidr
import kittoku.mvc.network.parseIPv4
import org.junit.Assert.*
import org.junit.Test

class BypassRoutesTest {
    private fun cidr(text: String): IPv4Cidr {
        val parts = text.split('/')
        return IPv4Cidr.of(parseIPv4(parts[0]), parts[1].toInt())
    }
    private fun assertRejected(operation: () -> Unit) {
        try { operation(); fail("Expected invalid bypass routes to be rejected") }
        catch (_: IllegalArgumentException) { }
    }

    @Test fun parserNormalizesAddressesCidrsAndExactIdnDomains() {
        val parsed = parseBypassRules("192.168.1.23/24, 10.0.0.5\nEXAMPLE.COM.;例子.测试")
        assertEquals(BypassRule.Network(cidr("192.168.1.0/24")), parsed[0])
        assertEquals(BypassRule.Network(cidr("10.0.0.5/32")), parsed[1])
        assertEquals(BypassRule.Domain("example.com"), parsed[2])
        assertEquals(BypassRule.Domain("xn--fsqu00a.xn--0zwm56d"), parsed[3])
    }

    @Test fun parserRejectsWildcardUrlsIpv6AndMalformedAddresses() {
        listOf("*.example.com", "https://example.com", "2001:db8::1", "[::1]", "1.2.3", "256.1.1.1",
            "1.2.3.4/33", "1.2.3.4/-1", "user@example.com", "bad..example", "_srv.example", "-bad.example")
            .forEach { rule -> assertRejected { parseBypassRules(rule) } }
    }

    @Test fun ruleLimitsPreventUnboundedDnsOrRouteExpansion() {
        assertRejected { parseBypassRules((1..17).joinToString("\n") { "domain$it.example" }) }
        assertRejected { parseBypassRules((1..129).joinToString("\n") { "10.0.0.1" }) }
        assertRejected { parseBypassRules("a".repeat(16_385)) }
    }
}
