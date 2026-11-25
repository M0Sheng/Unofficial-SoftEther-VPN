package kittoku.mvc.nativecore

import kittoku.mvc.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class SoftEtherErrorCatalogTest {
    @Test fun allPinnedCedarCodesHaveDistinctMessages() {
        val codes = (0..69) + (73..149)
        val messages = codes.map(::softEtherErrorResource)

        assertEquals(codes.size, messages.toSet().size)
        messages.forEach { assertNotEquals(R.string.softether_error_unknown, it) }
    }

    @Test fun undefinedAndFutureCodesKeepTheUnknownMeaning() {
        listOf(-1, 70, 71, 72, 150, Int.MAX_VALUE).forEach {
            assertEquals(R.string.softether_error_unknown, softEtherErrorResource(it))
        }
    }

    @Test fun connectionFailuresPreserveTheCedarMeanings() {
        assertEquals(R.string.softether_error_connect_failed, softEtherErrorResource(1))
        assertEquals(R.string.softether_error_hub_not_found, softEtherErrorResource(8))
        assertEquals(R.string.softether_error_auth_failed, softEtherErrorResource(9))
        assertEquals(R.string.softether_error_cert_not_trusted, softEtherErrorResource(85))
        assertEquals(R.string.softether_error_server_cert_expires, softEtherErrorResource(106))
        assertEquals(R.string.softether_error_dhcp_server_not_running, softEtherErrorResource(149))
    }
}
