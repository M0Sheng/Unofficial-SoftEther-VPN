package kittoku.mvc.tls

import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CertificateApprovalTest {
    private val createdAt = 1_000_000L
    private val endpoint = CertificateEndpoint.of("vpn.example", 5555)
    private val identity = CertificateIdentity(
        sha256 = "new-server-certificate",
        subject = "CN=vpn.example",
        issuer = "CN=vpn.example",
        notBeforeMillis = createdAt - 1_000L,
        notAfterMillis = createdAt + 1_000_000L,
        alternativeNames = "DNS:vpn.example",
    )
    private val approval = CertificateApproval(
        requestId = "request-1",
        profileId = "profile-a",
        endpoint = endpoint,
        backendMode = "ROOT_NATIVE",
        expectedSha256 = "",
        identity = identity,
        createdAtMillis = createdAt,
    )

    private fun CertificateApproval.accepts(
        requestId: String = this.requestId,
        currentProfileId: String = profileId,
        currentEndpoint: CertificateEndpoint = endpoint,
        currentBackendMode: String = backendMode,
        currentSavedSha256: String = expectedSha256,
        nowMillis: Long = createdAtMillis,
    ) = canAccept(requestId, currentProfileId, currentEndpoint, currentBackendMode, currentSavedSha256, nowMillis)

    @Test fun rejectsAnotherProfileEvenWithTheSameEndpointBackendAndSavedPin() {
        assertFalse(approval.accepts(currentProfileId = "profile-b"))
        assertFalse(approval.copy(profileId = "").accepts(currentProfileId = ""))
    }

    @Test fun namespacesPinsByProfileAsWellAsNormalizedEndpoint() {
        val first = CertificateProfileScope.key("profile-a", endpoint)
        assertEquals(first, CertificateProfileScope.key("profile-a", CertificateEndpoint.of("VPN.EXAMPLE", 5555)))
        assertNotEquals(first, CertificateProfileScope.key("profile-b", endpoint))
        assertNotEquals(first, CertificateProfileScope.key("profile-a", CertificateEndpoint.of("vpn.example", 443)))
    }

    @Test fun acceptsTheUnchangedDecisionAtBothTtlBoundaries() {
        assertTrue(approval.accepts())
        assertTrue(approval.accepts(nowMillis = createdAt + 600_000L))
        assertFalse(approval.accepts(nowMillis = createdAt + 600_001L))
    }

    @Test fun rejectsAnOldOrDifferentDialogRequest() {
        assertFalse(approval.accepts(requestId = "request-0"))
        assertFalse(approval.accepts(requestId = "REQUEST-1"))
    }

    @Test fun rejectsChangedHostPortOrBackend() {
        assertFalse(approval.accepts(currentEndpoint = CertificateEndpoint.of("other.example", 5555)))
        assertFalse(approval.accepts(currentEndpoint = CertificateEndpoint.of("vpn.example", 443)))
        assertFalse(approval.accepts(currentBackendMode = "TUN"))
    }

    @Test fun rejectsSavedTrustAddedReplacedOrRemovedWhileTheDialogWasOpen() {
        assertFalse(approval.accepts(currentSavedSha256 = identity.sha256))
        val replacingCertificate = approval.copy(expectedSha256 = "old-server-certificate")
        assertTrue(replacingCertificate.accepts())
        assertFalse(replacingCertificate.accepts(currentSavedSha256 = "different-server-certificate"))
        assertFalse(replacingCertificate.accepts(currentSavedSha256 = ""))
    }

    @Test fun rechecksCertificateDatesWhenTheUserAccepts() {
        val expiring = approval.copy(identity = identity.copy(notAfterMillis = createdAt + 1L))
        assertFalse(expiring.accepts(nowMillis = createdAt + 2L))
        val notYetValid = approval.copy(identity = identity.copy(notBeforeMillis = createdAt + 1L))
        assertFalse(notYetValid.accepts())
    }

    @Test fun rejectsClockRollbackAndTimestampOverflow() {
        assertFalse(approval.accepts(nowMillis = createdAt - 1L))
        val allTimeIdentity = identity.copy(notBeforeMillis = Long.MIN_VALUE, notAfterMillis = Long.MAX_VALUE)
        assertFalse(approval.copy(createdAtMillis = Long.MIN_VALUE, identity = allTimeIdentity)
            .accepts(nowMillis = Long.MAX_VALUE))
        assertFalse(approval.copy(createdAtMillis = Long.MAX_VALUE, identity = allTimeIdentity)
            .accepts(nowMillis = Long.MIN_VALUE))
    }

    @Test fun normalizesHostnameCaseIndependentlyOfTheDeviceLocale() {
        val previousLocale = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"))
            val normalized = CertificateEndpoint.of("  VPN.I.EXAMPLE  ", 5555)
            assertEquals("vpn.i.example", normalized.host)
            assertEquals(CertificateEndpoint.of("vpn.i.example", 5555), normalized)
            assertEquals(CertificateEndpoint.of("vpn.i.example", 5555).key, normalized.key)
        } finally {
            Locale.setDefault(previousLocale)
        }
    }

    @Test fun treatsBracketedIpv6AsTheSameEndpoint() {
        val bracketed = CertificateEndpoint.of("  [2001:DB8::A]  ", 5555)
        val unbracketed = CertificateEndpoint.of("2001:db8::a", 5555)
        assertEquals("2001:db8::a", bracketed.host)
        assertEquals(unbracketed, bracketed)
        assertEquals(unbracketed.key, bracketed.key)
        assertNotEquals(bracketed.key, CertificateEndpoint.of("[2001:db8::a]", 443).key)
    }

    @Test fun hashesTheNormalizedEndpointWithAnUnambiguousPortSeparator() {
        // SHA-256 of the UTF-8 bytes "vpn.example\n5555", independently calculated.
        assertEquals("26cf553a97ff14ff86638592238d6a786bcce879441b1d648f477b8097911b24", endpoint.key)
        assertEquals(64, endpoint.key.length)
        assertTrue(endpoint.key.matches(Regex("[0-9a-f]{64}")))
    }
}
