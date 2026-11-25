package kittoku.mvc.routing

import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TunDestinationRoutesTest {
    private fun cidr(text: String) = RootBypassCidr.parse(text)
    private fun ip(text: String): InetAddress = cidr(text).toInetAddress()
    private fun config(mode: TunDestinationMode, rules: String = "") = TunDestinationConfiguration(mode,
        includeRules = if (mode == TunDestinationMode.INCLUDE) rules else "",
        excludeRules = if (mode == TunDestinationMode.EXCLUDE) rules else "")

    @Test fun allIgnoresDormantMalformedListsAndDoesNotEnableDisabledIpv6() {
        val configuration = TunDestinationConfiguration(TunDestinationMode.ALL, "bad://input", "::not-an-ip")
        val plan = planTunDestinationRoutes(configuration, false)
        assertEquals(listOf("0.0.0.0/0"), plan.ipv4.included.map { it.canonical })
        assertTrue(plan.ipv4.captures(ip("192.0.2.1")))
        assertFalse(plan.ipv6.hasRoutes)
        assertFalse(plan.captures(ip("2001:db8::1")))
        assertTrue(planTunDestinationRoutes(configuration, true).ipv6.hasRoutes)
    }

    @Test fun includeOnlyCapturesSpecifiedDualStackAddresses() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.INCLUDE, "192.0.2.99/24 2001:db8::/64"), true)
        assertTrue(plan.captures(ip("192.0.2.1").address))
        assertFalse(plan.captures(ip("192.0.3.1")))
        assertTrue(plan.captures(ip("2001:db8::5")))
        assertFalse(plan.captures(ip("2001:db8:1::5")))
        assertTrue(plan.ipv4.excluded.isEmpty())
        assertTrue(plan.ipv6.excluded.isEmpty())
    }

    @Test fun excludeKeepsDefaultsAndOnlyExcludesMatchingFamily() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "192.0.2.0/24 2001:db8::/64"), true)
        assertEquals(listOf("0.0.0.0/0"), plan.ipv4.included.map { it.canonical })
        assertEquals(listOf("::/0"), plan.ipv6.included.map { it.canonical })
        assertFalse(plan.captures(ip("192.0.2.1")))
        assertTrue(plan.captures(ip("198.51.100.1")))
        assertFalse(plan.captures(ip("2001:db8::1")))
        assertTrue(plan.captures(ip("2001:db8:1::1")))
    }

    @Test fun twoIpv4HalvesOmitOnlyIpv4WithoutClaimingItIsCaptured() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "0.0.0.0/1 128.0.0.0/1"), true)
        assertFalse(plan.ipv4.hasRoutes)
        assertTrue(plan.ipv4.included.isEmpty())
        assertTrue(plan.ipv4.excluded.isEmpty())
        assertTrue(plan.ipv6.hasRoutes)
        assertFalse(plan.captures(ip("203.0.113.3")))
    }

    @Test fun twoIpv6HalvesOmitIpv6AndKeepIpv4() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "::/1 8000::/1"), true)
        assertTrue(plan.ipv4.hasRoutes)
        assertFalse(plan.ipv6.hasRoutes)
        assertTrue(plan.ipv6.included.isEmpty())
        assertFalse(plan.captures(ip("2001:db8::3")))
    }

    @Test fun rejectsNoRemainingRoutesIncludingCoverageBySiblingPrefixes() {
        assertThrows(IllegalArgumentException::class.java) {
            planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "0.0.0.0/1 128.0.0.0/1 ::/1 8000::/1"), true)
        }
        assertThrows(IllegalArgumentException::class.java) {
            planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "0.0.0.0/0"), false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            planTunDestinationRoutes(config(TunDestinationMode.INCLUDE), true)
        }
    }

    @Test fun includeMayIntentionallyHaveOnlyOneFamily() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.INCLUDE, "2001:db8::/64"), true)
        assertFalse(plan.ipv4.hasRoutes)
        assertTrue(plan.ipv6.hasRoutes)
        assertFalse(plan.ipv4.captures(ip("1.1.1.1")))
    }

    @Test fun disabledIpv6RejectsActiveNumericIpv6RulesInEitherMode() {
        listOf(TunDestinationMode.INCLUDE, TunDestinationMode.EXCLUDE).forEach { mode ->
            assertThrows(IllegalArgumentException::class.java) {
                planTunDestinationRoutes(config(mode, "192.0.2.1 2001:db8::1"), false)
            }
        }
    }

    @Test fun exactDomainsCaptureAAndAaaaFromTheSameSuppliedSnapshot() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.INCLUDE, "BÜCHER.Example. shared.example"), true,
            mapOf("xn--bcher-kva.example" to listOf(ip("192.0.2.10"), ip("2001:db8::10"), ip("192.0.2.10")),
                "shared.example" to listOf(ip("192.0.2.10"))))
        assertEquals(listOf("192.0.2.10/32"), plan.ipv4.included.map { it.canonical })
        assertEquals(listOf("2001:db8::10/128"), plan.ipv6.included.map { it.canonical })
        assertEquals(2, plan.domains.size)
        assertFalse(plan.captures(ip("192.0.2.11")))
    }

    @Test fun disabledIpv6UsesOnlyAAndRejectsAaaaOnlyRatherThanFallingBack() {
        val configuration = config(TunDestinationMode.INCLUDE, "dual.example")
        val plan = planTunDestinationRoutes(configuration, false,
            mapOf("dual.example" to listOf(ip("192.0.2.10"), ip("2001:db8::10"))))
        assertTrue(plan.captures(ip("192.0.2.10")))
        assertFalse(plan.ipv6.hasRoutes)
        assertEquals(listOf("192.0.2.10/32"), plan.domains.single().addresses.map { it.canonical })
        assertThrows(IllegalArgumentException::class.java) {
            planTunDestinationRoutes(configuration, false, mapOf("dual.example" to listOf(ip("2001:db8::10"))))
        }
    }

    @Test fun rejectsMissingOrUnusableDnsSnapshots() {
        val configuration = config(TunDestinationMode.INCLUDE, "a.example")
        assertThrows(IllegalArgumentException::class.java) { planTunDestinationRoutes(configuration, true) }
        assertThrows(IllegalArgumentException::class.java) {
            planTunDestinationRoutes(configuration, true, mapOf("a.example" to listOf(ip("::1"), ip("fe80::1"), ip("224.0.0.1"))))
        }
    }

    @Test fun coveredDnsMustActuallyBeCapturedAfterExclusions() {
        val plan = planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "192.0.2.53 1.1.1.1"), true)
        assertFalse(plan.ipv4.captures(ip("192.0.2.53")))
        assertFalse(plan.ipv4.captures(ip("1.1.1.1")))
        assertTrue(plan.ipv4.captures(ip("8.8.8.8")))
        assertTrue(plan.ipv6.captures(ip("2001:db8::53")))
    }

    @Test fun hasRoutesOutsideAccountsForCoveredPrefixesNotJustListEntries() {
        val inside = planTunDestinationRoutes(config(TunDestinationMode.INCLUDE, "192.0.2.5 192.0.2.128/25 2001:db8::/64"), true)
        assertFalse(inside.ipv4.hasRoutesOutside(cidr("192.0.2.0/24")))
        assertFalse(inside.ipv6.hasRoutesOutside(cidr("2001:db8::/64")))
        assertTrue(inside.ipv4.hasRoutesOutside(cidr("192.0.2.0/25")))
        val half = planTunDestinationRoutes(config(TunDestinationMode.EXCLUDE, "128.0.0.0/1"), false)
        assertFalse(half.ipv4.hasRoutesOutside(cidr("0.0.0.0/1")))
        assertTrue(half.ipv4.hasRoutesOutside(cidr("192.0.2.0/24")))
    }

    @Test fun refusesWhollyUnsupportedIncludePrefixesButAllowsUnicastDefaults() {
        for (text in listOf("0.0.0.0", "127.1.0.0/16", "224.0.0.0/4", "255.255.255.255", "::", "::1", "::/127", "fe80::/64", "ff00::/8")) {
            assertThrows("must reject $text", IllegalArgumentException::class.java) {
                planTunDestinationRoutes(config(TunDestinationMode.INCLUDE, text), true)
            }
        }
        val plan = planTunDestinationRoutes(config(TunDestinationMode.INCLUDE, "0.0.0.0/0 ::/0"), true)
        assertTrue(plan.captures(ip("192.0.2.1")))
        assertTrue(plan.captures(ip("2001:db8::1")))
    }

    @Test fun packetMembershipUsesDefensiveNumericBytesAndKeepsFamilySeparate() {
        val prefix = cidr("2001:db8::/64")
        val copy = prefix.addressBytes()
        copy.fill(0)
        assertTrue(prefix.containsAddress(ip("2001:db8::1").address))
        assertFalse(prefix.containsAddress(ip("192.0.2.1").address))
        assertFalse(prefix.containsAddress(ByteArray(15)))
        val (left, right) = prefix.split()
        assertEquals("2001:db8::/65", left.canonical)
        assertEquals("2001:db8:0:0:8000::/65", right.canonical)
    }

    @Test fun prefixSurvivalMatchesExhaustiveSmallSubnetWithoutEnumeratingInProduction() {
        repeat(32) { mask ->
            val excluded = (0 until 5).filter { mask and (1 shl it) != 0 }.map { cidr("192.0.2.${it * 32}/27") }
            val family = TunDestinationFamilyRoutes(4, listOf(cidr("192.0.2.0/24")), excluded)
            val survivors = (0..255).filter { family.captures(ip("192.0.2.$it")) }
            assertEquals(survivors.isNotEmpty(), family.hasRoutes)
            assertEquals(survivors.any { it >= 128 }, family.hasRoutesOutside(cidr("192.0.2.0/25")))
        }
    }

    @Test fun resolverQueriesOnlyNormalizedExactDomainsAndNeverDormantRules() {
        val queried = mutableListOf<String>()
        val checks = AtomicInteger()
        val plan = resolveTunDestinationRules(config(TunDestinationMode.INCLUDE, "EXACT.Example."), true,
            checkAvailable = { checks.incrementAndGet(); Unit }, lookup = { host ->
                synchronized(queried) { queried += host }
                listOf(ip("192.0.2.9"), ip("2001:db8::9"))
            })
        assertEquals(listOf("exact.example"), queried)
        assertEquals(2, checks.get())
        assertTrue(plan.captures(ip("2001:db8::9")))
        resolveTunDestinationRules(TunDestinationConfiguration(TunDestinationMode.ALL, "not://a/domain", "hidden.example"), true,
            checkAvailable = { throw AssertionError("ALL needs no DNS network") },
            lookup = { throw AssertionError("ALL must not resolve dormant domains") })
    }

    @Test fun numericRulesDoNotRequireOrProbeDnsNetwork() {
        val plan = resolveTunDestinationRules(config(TunDestinationMode.INCLUDE, "192.0.2.0/24 2001:db8::/64"), true,
            checkAvailable = { throw AssertionError("numeric policy needs no DNS network") },
            lookup = { throw AssertionError("numeric policy must not query DNS") })
        assertTrue(plan.ipv4.hasRoutes)
        assertTrue(plan.ipv6.hasRoutes)
    }

    @Test fun detachedNetworkFailsBeforeDnsAndDoesNotUseGlobalResolver() {
        assertThrows(IOException::class.java) {
            resolveTunDestinationRules(config(TunDestinationMode.INCLUDE, "a.example"), true,
                checkAvailable = { throw IOException("detached") },
                lookup = { throw AssertionError("must not resolve after detach") })
        }
    }

    @Test fun disappearingNetworkRejectsEvenAnOtherwiseValidCachedAnswer() {
        val checks = AtomicInteger()
        assertThrows(IOException::class.java) {
            resolveTunDestinationRules(config(TunDestinationMode.INCLUDE, "a.example"), true,
                checkAvailable = { if (checks.incrementAndGet() == 2) throw IOException("lost") },
                lookup = { listOf(ip("192.0.2.3")) })
        }
        assertEquals(2, checks.get())
    }

    @Test fun unresolvedDomainFailsWithOriginalCauseAndNoFallbackLookup() {
        val calls = AtomicInteger()
        val error = assertThrows(IOException::class.java) {
            resolveTunDestinationRules(config(TunDestinationMode.INCLUDE, "missing.example"), false,
                checkAvailable = {}, lookup = { calls.incrementAndGet(); throw UnknownHostException("missing.example") })
        }
        assertTrue(error.cause is UnknownHostException)
        assertEquals(1, calls.get())
    }
}
