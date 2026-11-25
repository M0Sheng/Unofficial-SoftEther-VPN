package kittoku.mvc.routing

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RootBypassRulesTest {
    private fun cidr(text: String) = RootBypassCidr.parse(text)
    private fun rules(text: String) = RootBypassRules.parse(text)
    private fun address(vararg bytes: Int): InetAddress = InetAddress.getByAddress(bytes.map { it.toByte() }.toByteArray())
    private fun ipv6(vararg tail: Int): InetAddress = InetAddress.getByAddress(ByteArray(16).also { bytes ->
        bytes[0] = 0x20; bytes[1] = 0x01; bytes[2] = 0x0d; bytes[3] = 0xb8.toByte()
        tail.forEachIndexed { index, value -> bytes[16 - tail.size + index] = value.toByte() }
    })

    @Test fun normalizesHostBitsAndSingleAddressesInBothFamilies() {
        assertEquals("192.168.1.0/24", cidr("192.168.1.199/24").canonical)
        assertEquals("192.168.1.199/32", cidr("192.168.1.199").canonical)
        assertEquals("2001:db8:abcd:1234::/64", cidr("2001:DB8:ABCD:1234:5678:9999:AAAA:BBBB/64").canonical)
        assertEquals("2001:db8::1/128", cidr("[2001:0DB8::0001]").canonical)
        assertEquals(4, cidr("1.2.3.4").family)
        assertEquals(6, cidr("::1").family)
    }

    @Test fun supportsZeroPrefixesAndMasksPartialBytes() {
        assertEquals("0.0.0.0/0", cidr("198.51.100.23/0").canonical)
        assertEquals("::/0", cidr("2001:db8::1234/0").canonical)
        assertEquals("192.168.0.0/17", cidr("192.168.127.255/17").canonical)
        assertEquals("2001:db8:0:0:8000::/65", cidr("2001:db8:0:0:ffff:ffff:ffff:ffff/65").canonical)
        assertTrue(cidr("::/0").contains(cidr("2001:db8::1")))
        assertFalse(cidr("::/0").contains(cidr("192.0.2.1")))
    }

    @Test fun formatsIpv6CompressionUsingLongestRunAndFirstTie() {
        assertEquals("::/128", cidr("0:0:0:0:0:0:0:0").canonical)
        assertEquals("1::/128", cidr("1:0:0:0:0:0:0:0").canonical)
        assertEquals("1::2:0:0:3:4/128", cidr("1:0:0:2:0:0:3:4").canonical)
        assertEquals("1:0:2:3:4:5:6:7/128", cidr("1:0:2:3:4:5:6:7").canonical)
    }

    @Test fun supportsNumericNat64EmbeddedIpv4ButRejectsMappedAddresses() {
        assertEquals("64:ff9b::c000:221/128", cidr("64:ff9b::192.0.2.33").canonical)
        assertThrows(IllegalArgumentException::class.java) { cidr("::ffff:192.0.2.1") }
    }

    @Test fun rejectsMalformedNumbersPrefixesScopesAndPorts() {
        for (text in listOf("1.2.3", "256.2.3.4", "01.2.3.4", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/", ":", ":::1",
            "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8", "2001:db8::1/129",
            "fe80::1%wlan0", "[2001:db8::1]:9930", "[192.0.2.1]", "1.2.3.4:443", "2001:gggg::1")) {
            assertThrows("must reject $text", IllegalArgumentException::class.java) { cidr(text) }
        }
    }

    @Test fun normalizesIdnCaseTrailingDotAndDeduplicatesEquivalentRules() {
        val parsed = rules("BÜCHER.Example., xn--bcher-kva.example;192.168.1.1/24 192.168.1.0/24\n2001:db8::1/64 2001:0db8::/64")
        assertEquals(3, parsed.size)
        assertEquals(RootBypassRule.Domain("xn--bcher-kva.example"), parsed[0])
        assertEquals(RootBypassRule.Domain("xn--bcher-kva.example"), rules("bücher。example。").single())
        assertEquals(RootBypassRule.Network(cidr("192.0.2.1")), rules("１９２。０。２。１").single())
    }

    @Test fun neverPassesLegacyNumericIpSyntaxToTheDnsResolver() {
        for (text in listOf("0xC0000201", "0xC0.0.2.1", "3221225985", "192.0.2", "0192.0.2.1")) {
            assertThrows("must reject ambiguous numeric address $text", IllegalArgumentException::class.java) { rules(text) }
        }
    }

    @Test fun rejectsWildcardUrlShellAndInvalidDnsLabels() {
        for (text in listOf("*.example.com", "https://example.com", "example.com:443", "a..example", "-a.example", "a_.example", "a.example/path", "a.example#x", "a.example\u0000x", "$(id).example", "a`id`.example")) {
            assertThrows("must reject $text", IllegalArgumentException::class.java) { rules(text) }
        }
    }

    @Test fun enforcesInputRuleAndDomainLimits() {
        assertTrue(rules("").isEmpty())
        assertEquals(128, rules((1..128).joinToString(" ") { "10.0.0.$it" }).size)
        assertThrows(IllegalArgumentException::class.java) { rules((1..129).joinToString(" ") { "10.0.0.$it" }) }
        assertEquals(16, rules((1..16).joinToString(" ") { "d$it.example" }).size)
        assertThrows(IllegalArgumentException::class.java) { rules((1..17).joinToString(" ") { "d$it.example" }) }
        assertThrows(IllegalArgumentException::class.java) { rules("a".repeat(16_385)) }
    }

    @Test fun plansBothDnsFamiliesAndCoalescesCoveredHostsAndDuplicateAnswers() {
        val resolved = mapOf("a.example" to listOf(address(192, 0, 2, 9), ipv6(1), ipv6(1)),
            "b.example" to listOf(address(192, 0, 2, 9)))
        val plan = RootBypassRules.plan(rules("192.0.2.99/24 a.example b.example 2001:db8::/64"), resolved)
        assertEquals(listOf("192.0.2.0/24", "2001:db8::/64"), plan.cidrs)
        assertEquals(2, plan.domains.size)
        assertEquals(listOf("192.0.2.9/32", "2001:db8::1/128"), plan.domains[0].addresses.map { it.canonical })
    }

    @Test fun keepsFamiliesSeparateWhenOneIsEntirelyBypassed() {
        val plan = RootBypassRules.plan(rules("0.0.0.0/0 1.2.3.4 ::/0 2001:db8::1"))
        assertEquals(listOf("0.0.0.0/0", "::/0"), plan.cidrs)
    }

    @Test fun rejectsMissingEmptyUnusableAndOversizedDnsSnapshots() {
        val parsed = rules("a.example")
        assertThrows(IllegalArgumentException::class.java) { RootBypassRules.plan(parsed) }
        assertThrows(IllegalArgumentException::class.java) { RootBypassRules.plan(parsed, mapOf("a.example" to emptyList())) }
        assertThrows(IllegalArgumentException::class.java) { RootBypassRules.plan(parsed, mapOf("a.example" to listOf(
            address(0, 0, 0, 0), address(127, 0, 0, 1), address(169, 254, 1, 1), address(224, 0, 0, 1), address(255, 255, 255, 255)))) }
        assertThrows(IllegalArgumentException::class.java) { RootBypassRules.plan(parsed,
            mapOf("a.example" to List(65) { address(192, 0, 2, 1) })) }
    }

    @Test fun boundsExpandedPlanAndAllowsExactlyTheMaximumUniqueHosts() {
        fun snapshot(domains: Int) = (1..domains).associate { domain -> "d$domain.example" to
            (1..64).map { host -> address(10, domain, 0, host) } }
        val maximum = RootBypassRules.plan(rules((1..4).joinToString(" ") { "d$it.example" }), snapshot(4))
        assertEquals(256, maximum.networks.size)
        assertThrows(IllegalArgumentException::class.java) {
            RootBypassRules.plan(rules((1..5).joinToString(" ") { "d$it.example" }), snapshot(5))
        }
    }
}
