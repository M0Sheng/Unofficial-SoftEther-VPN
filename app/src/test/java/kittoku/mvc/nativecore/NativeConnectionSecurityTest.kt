package kittoku.mvc.nativecore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.HexFormat

class NativeConnectionSecurityTest {
    @Test fun reportsOnlyNativeNegotiationAndExactPeerIdentity() {
        val leaf = certificate()
        val reader = NativeConnectionSecurityReader(pem(leaf))
        val status = checkNotNull(reader.read(rows(leaf.encoded)))
        assertEquals("TLSv1.3", status.tlsVersion)
        assertEquals("TLS_AES_256_GCM_SHA384", status.cipherSuite)
        assertEquals(true, status.encryptionEnabled)
        assertEquals(NativeCertificateVerification.SYSTEM_CA, status.verification)
        val identity = checkNotNull(status.serverCertificate)
        assertEquals(leaf.subjectX500Principal.name, identity.subject)
        assertEquals(leaf.issuerX500Principal.name, identity.issuer)
        assertEquals(leaf.notAfter.time, identity.expiresAtMillis)
        assertEquals(digest(leaf, "SHA-1"), identity.sha1)
        assertEquals(digest(leaf, "SHA-256"), identity.sha256)
    }

    @Test fun savedPinIsReportedOnlyWhenNativeVerifiedTheSameLeaf() {
        val leaf = certificate()
        val reader = NativeConnectionSecurityReader(pem(leaf), digest(leaf, "SHA-256"))
        assertEquals(NativeCertificateVerification.SAVED_PIN, reader.read(rows(leaf.encoded))?.verification)
        assertEquals(NativeCertificateVerification.UNVERIFIED,
            reader.read(rows(leaf.encoded) + ("Server Certificate Verified" to "0"))?.verification)
        assertEquals(NativeCertificateVerification.UNKNOWN,
            reader.read(rows(leaf.encoded) - "Server Certificate Verified")?.verification)
        val anotherLeaf = certificate("future")
        val different = reader.read(rows(anotherLeaf.encoded))
        assertEquals(NativeCertificateVerification.NATIVE_VERIFIED, different?.verification)
        assertEquals(digest(anotherLeaf, "SHA-256"), different?.serverCertificate?.sha256)
    }

    @Test fun ignoresNonEstablishedStateAndMissingTelemetry() {
        val reader = NativeConnectionSecurityReader()
        assertNull(reader.read(rows(certificate().encoded) + ("Session Status" to "Retrying")))
        assertNull(reader.read(mapOf("Session Status" to ESTABLISHED, "Encryption" to "Enabled")))
    }

    @Test fun acceptsExplicitEncryptionOffAndRejectsMalformedCertificateFields() {
        val reader = NativeConnectionSecurityReader()
        val original = certificate().encoded
        val status = checkNotNull(reader.read(rows(original + byteArrayOf(0)) + mapOf(
            "VPN Payload Encryption" to "0", "TLS Version" to "n/a", "Server Certificate Verified" to "?",
        )))
        assertEquals(false, status.encryptionEnabled)
        assertEquals(NativeCertificateVerification.UNKNOWN, status.verification)
        assertNull(status.tlsVersion)
        assertNull(status.serverCertificate)
        assertEquals(NativeCertificateVerification.NATIVE_VERIFIED, reader.read(rows(original))?.verification)
    }

    private fun rows(der: ByteArray) = mapOf(
        "Session Status" to ESTABLISHED,
        "TLS Version" to "TLSv1.3",
        "TLS Cipher Suite" to "TLS_AES_256_GCM_SHA384",
        "VPN Payload Encryption" to "1",
        "Server Certificate DER" to Base64.getEncoder().encodeToString(der),
        "Server Certificate Verified" to "1",
    )

    private fun certificate(fixture: String = "localhost"): X509Certificate = KeyStore.getInstance("PKCS12").apply {
        val stream = checkNotNull(NativeConnectionSecurityTest::class.java.getResourceAsStream("/tls/$fixture.p12"))
        stream.use { load(it, "test-only".toCharArray()) }
    }.getCertificate("test-server") as X509Certificate

    private fun pem(certificate: X509Certificate): ByteArray {
        val body = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(certificate.encoded)
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n".toByteArray(Charsets.US_ASCII)
    }

    private fun digest(certificate: X509Certificate, algorithm: String) =
        HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(certificate.encoded))

    private companion object {
        const val ESTABLISHED = "Connection Completed (Session Established)"
    }
}
