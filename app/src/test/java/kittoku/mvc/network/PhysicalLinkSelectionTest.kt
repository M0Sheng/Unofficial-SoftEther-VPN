package kittoku.mvc.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhysicalLinkSelectionTest {
    @Test fun waitsForReplacementAddressAndIgnoresLateEvents() {
        val links = PhysicalLinkSelection<String>()
        assertTrue(links.offer("wifi"))
        assertTrue(links.addressChanged("wifi", usable = true))
        assertEquals("wifi", links.ready)

        assertTrue(links.lost("wifi"))
        assertTrue(links.offer("mobile"))
        assertFalse(links.addressChanged("wifi", usable = true))
        assertFalse(links.addressChanged("mobile", usable = false))
        assertNull(links.ready)
        assertTrue(links.addressChanged("mobile", usable = true))
        assertEquals("mobile", links.ready)
    }

    @Test fun replacesRetainedMobileWhenWifiBecomesPreferred() {
        val links = PhysicalLinkSelection<String>()
        assertTrue(links.offer("mobile"))
        assertTrue(links.addressChanged("mobile", usable = true))

        assertTrue(links.offer("wifi"))
        assertNull(links.ready)
        assertFalse(links.lost("mobile"))
        assertTrue(links.addressChanged("wifi", usable = true))
        assertEquals("wifi", links.ready)
        assertFalse(links.offer("wifi"))
        assertFalse(links.addressChanged("wifi", usable = true))
    }
}
