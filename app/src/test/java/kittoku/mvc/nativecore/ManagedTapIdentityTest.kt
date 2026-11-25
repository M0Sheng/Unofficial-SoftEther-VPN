package kittoku.mvc.nativecore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ManagedTapIdentityTest {
    private val token = "36b82243-8746-4def-93bd-28d032882ca9"

    @Test fun bindsProofToTheSelectedInterfaceAndItsIndex() {
        assertEquals(ManagedTapIdentity("usb2", 174),
            ManagedTapIdentity.parseCreation("HOMEVPN_TAP_CREATED $token usb2 174", token, "usb2"))
        assertNull(ManagedTapIdentity.parseCreation("HOMEVPN_TAP_CREATED $token eth2 174", token, "usb2"))
        assertNull(ManagedTapIdentity.parseCreation("HOMEVPN_TAP_CREATED stale-token usb2 174", token, "usb2"))
    }

    @Test fun rejectsUnsafeNamesAndMalformedOrMissingInterfaceIndices() {
        for (index in listOf("0", "-1", "+1", "2147483648", "2 suffix", "")) {
            assertNull(ManagedTapIdentity.parseCreation("HOMEVPN_TAP_CREATED $token eth1 $index", token, "eth1"))
        }
        assertNull(ManagedTapIdentity.parseCreation("HOMEVPN_TAP_CREATED $token wlan0 4", token, "wlan0"))
        assertNull(ManagedTapIdentity.parseCreation("LOG HOMEVPN_TAP_CREATED $token eth1 4", token, "eth1"))
    }
}
