package kittoku.mvc.control

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RustTunAddressSnapshotTest {
    @Test
    fun readsIpv4LeaseAndIpv6PrefixFromTheSameUpdate() {
        val ipv6 = InetAddress.getByName("2001:db8::21")
        val prefix = InetAddress.getByName("2001:db8::")
        val state = buffer()
            .putInt(1).putInt(2) // Lease present, IPv6 ready.
            .putInt(0xc000020a.toInt()).putInt(24).putInt(1).putInt(2)
            .putInt(0xc0000201.toInt())
            .putInt(0).putInt(0).putInt(0xc0000201.toInt())
            .putInt(0xc6336400.toInt()).putInt(24).putInt(0)
            .put(ipv6.address).putInt(1420).putInt(3).put(prefix.address)
        state.flip()

        val update = decodeTunAddresses(state)
        assertFalse(update.leaseLost)
        assertEquals(NativeTunIpv6Status.READY, update.ipv6Status)
        assertEquals(NativeTunIpv6Configuration(ipv6 as java.net.Inet6Address, prefix as java.net.Inet6Address, 1420, true),
            update.ipv6)
        val lease = requireNotNull(update.lease)
        assertEquals(0xc000020a.toInt(), lease.address)
        assertEquals(listOf(0xc0000201.toInt()), lease.dns)
        assertEquals(listOf(NativeTunIpv4Route(0, 0, 0xc0000201.toInt()),
            NativeTunIpv4Route(0xc6336400.toInt(), 24, 0)), lease.routes)
        assertFalse(requireNotNull(update.ipv6).address.hostAddress.orEmpty().contains('%'))
    }

    @Test
    fun leaseLossCanBeReportedWithoutAReplacementAddress() {
        val state = buffer().putInt(2).putInt(5) // Lease lost, IPv6 timed out.
        state.flip()
        val update = decodeTunAddresses(state)
        assertTrue(update.leaseLost)
        assertNull(update.lease)
        assertEquals(NativeTunIpv6Status.NO_ADVERTISEMENT, update.ipv6Status)
        assertNull(update.ipv6)
    }

    private fun buffer(): ByteBuffer = ByteBuffer.allocate(128).order(ByteOrder.nativeOrder())
}
