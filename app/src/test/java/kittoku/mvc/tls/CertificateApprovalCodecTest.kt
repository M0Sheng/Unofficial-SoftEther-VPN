package kittoku.mvc.tls

import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class CertificateApprovalCodecTest {
    private val value = CertificateApproval("review-1", "profile-a", CertificateEndpoint.of("vpn.example", 5555),
        "ROOT_NATIVE", "ab".repeat(32), CertificateIdentity("cd".repeat(32), "CN=家庭 VPN\nsecond line",
            "CN=测试 CA", 1_000, 100_000, "DNS:vpn.example, IP:192.0.2.1"), 50_000)

    @Test fun roundTripsTheFrozenProfileEndpointBackendAndPublicCertificateMetadata() {
        assertEquals(value, CertificateApprovalCodec.decode(CertificateApprovalCodec.encode(value)))
    }

    @Test fun refusesLegacyUnscopedJsonAndUnknownVersions() {
        assertThrows(IllegalArgumentException::class.java) { CertificateApprovalCodec.decode("{\"id\":\"old\"}") }
        assertThrows(IllegalArgumentException::class.java) { CertificateApprovalCodec.decode("profile-v2:anything") }
    }

    @Test fun rejectsTruncatedOrAppendedBinaryData() {
        val encoded = CertificateApprovalCodec.encode(value)
        assertThrows(Exception::class.java) { CertificateApprovalCodec.decode(encoded.dropLast(8)) }
        val bytes = Base64.getDecoder().decode(encoded.substringAfter(':')) + byteArrayOf(0)
        assertThrows(IllegalArgumentException::class.java) {
            CertificateApprovalCodec.decode("profile-v1:" + Base64.getEncoder().encodeToString(bytes))
        }
    }

    @Test fun rejectsMissingProfileInvalidPinsAndOversizedRecords() {
        for (invalid in listOf(value.copy(profileId = ""), value.copy(expectedSha256 = "not-a-sha256"),
            value.copy(identity = value.identity.copy(sha256 = "")),
            value.copy(identity = value.identity.copy(subject = "a".repeat(8193))))) {
            assertThrows(IllegalArgumentException::class.java) { CertificateApprovalCodec.encode(invalid) }
        }
        assertThrows(IllegalArgumentException::class.java) { CertificateApprovalCodec.decode("profile-v1:" + "a".repeat(96 * 1024)) }
    }
}
