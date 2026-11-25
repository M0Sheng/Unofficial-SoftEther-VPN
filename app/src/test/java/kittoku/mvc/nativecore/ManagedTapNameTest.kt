package kittoku.mvc.nativecore

import org.junit.Assert.*
import org.junit.Test

class ManagedTapNameTest {
    @Test fun safeNamesAreAsciiAndFitTheLinuxLimit() {
        listOf("eth0", "usb17", "eth123456789012", "usb000000000000").forEach {
            assertTrue(it, ManagedTapName.isValid(it)); assertTrue(it.length <= 15)
        }
        listOf("eth", "eth-1", "ETH0", "tap0", "eth١", "usb０", "eth1234567890123",
            "eth0;id", "eth0\n", " usb1", "usb1 ", "../eth0").forEach {
            assertFalse(it, ManagedTapName.isValid(it))
        }
    }

    @Test fun defaultSentinelSelectsAnUnoccupiedEthernetName() {
        assertEquals("eth2", ManagedTapName.selectFromPolicy(setOf("eth0", "eth1"), "*"))
    }

    @Test fun oemSingleDigitRestrictionIsHonored() {
        assertEquals("eth9", ManagedTapName.selectFromPolicy((0..8).map { "eth$it" }.toSet(), "eth\\d"))
        fails { ManagedTapName.selectFromPolicy((0..9).map { "eth$it" }.toSet(), "eth\\d") }
    }

    @Test fun usbOnlyRuleDoesNotSilentlyChooseEthernet() {
        assertEquals("usb3", ManagedTapName.selectFromPolicy(setOf("usb0", "usb1", "usb2"), "usb[0-9]+"))
    }

    @Test fun configuredInterfacesAreReservedEvenWhilePhysicallyAbsent() {
        val config = listOf("eth0;;ip=192.0.2.1/24", "eth1;12,13;;1", " eth2 ;*", "usb0;;")
        assertEquals("eth3", ManagedTapName.selectFromPolicy(emptySet(), "*", config))
    }

    @Test fun readableEmptyOrUnrelatedRulesNeverFallBack() {
        fails { ManagedTapName.selectFromPolicy(emptySet(), "") }
        fails { ManagedTapName.selectFromPolicy(emptySet(), "vpn_.*") }
        fails { ManagedTapName.selectFromPolicy(emptySet(), "eth0|usb0", listOf("eth0;;", "usb0;;")) }
    }

    @Test fun regexMustMatchTheWholeSafeInterfaceName() {
        fails { ManagedTapName.selectFromPolicy(emptySet(), "th[0-9]+") }
        assertEquals("eth0", ManagedTapName.selectFromPolicy(emptySet(), ".*"))
    }

    @Test fun malformedOrExcessiveReadableRulesFailExplicitly() {
        fails { ManagedTapName.selectFromPolicy(emptySet(), "[") }
        fails { ManagedTapName.selectFromPolicy(emptySet(), "x".repeat(4097)) }
    }

    @Test fun unreadPolicyUsesOnlySingleDigitEthernetAndStillAvoidsConfiguredInterfaces() {
        val occupied = (0..7).map { "eth$it" }.toSet()
        assertEquals("eth9", ManagedTapName.selectFromPolicy(occupied, null, listOf("eth8;;")))
        fails { ManagedTapName.selectFromPolicy((0..9).map { "eth$it" }.toSet(), null) }
    }

    @Test fun numericAlternativesAndLongOemNamesRemainPossible() {
        assertEquals("eth123456789012", ManagedTapName.selectFromPolicy(emptySet(), "eth123456789012"))
        assertEquals("usb01", ManagedTapName.selectFromPolicy(emptySet(), "usb01"))
        assertTrue(ManagedTapName.selectFromPolicy(emptySet(), "eth[1-9]{12}").matches(Regex("eth[1-9]{12}")))
    }

    @Test fun systemMarkerOrPackageNameAloneCannotMakeResourcesTrusted() {
        val path = "/apex/com.android.tethering/priv-app/ServiceConnectivityResources/ServiceConnectivityResources.apk"
        assertTrue(ManagedTapName.isTrustedPackage(1, path))
        assertFalse(ManagedTapName.isTrustedPackage(0, path))
        assertFalse(ManagedTapName.isTrustedPackage(1, "/data/app/com.android.connectivity.resources/base.apk"))
        assertFalse(ManagedTapName.isTrustedPackage(1, "/apex/com.android.tethering.evil/base.apk"))
        assertFalse(ManagedTapName.isTrustedPackage(1, "/apex/com.android.tethering/../evil/base.apk"))
        assertFalse(ManagedTapName.isTrustedPackage(1, null))
    }

    @Test fun everyReturnedCandidatePassesAllThreeIndependentFilters() {
        val rule = "(?:eth|usb)[02468]"
        val occupied = setOf("eth0", "eth2", "eth4")
        val configured = listOf("eth6;;", "eth8;;")
        val selected = ManagedTapName.selectFromPolicy(occupied, rule, configured)
        assertEquals("usb0", selected)
        assertTrue(ManagedTapName.isValid(selected))
        assertTrue(Regex(rule).matches(selected))
        assertFalse(occupied.contains(selected))
        assertFalse(configured.any { it.substringBefore(';') == selected })
    }

    private fun fails(block: () -> Unit) {
        try { block(); fail("Expected explicit failure") } catch (_: IllegalStateException) { }
    }
}
