package kittoku.mvc.tls

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager

/** Real local TLS handshakes; test keys are public fixtures, never production credentials. */
class ReviewingTrustManagerTest {
    @Test fun identityUsesCompleteDerCertificateAndContainsSans() {
        val certificate = certificate()
        val identity = CertificateIdentity.from(certificate)
        val expected = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals(expected, identity.sha256)
        assertEquals(64, identity.sha256.length)
        assertEquals(certificate.subjectX500Principal.name, identity.subject)
        assertEquals(certificate.issuerX500Principal.name, identity.issuer)
        assertTrue(identity.alternativeNames.contains("DNS:localhost"))
        assertTrue(identity.alternativeNames.contains("IP:127.0.0.1"))
        assertEquals(certificate.notBefore.time, identity.notBeforeMillis)
        assertEquals(certificate.notAfter.time, identity.notAfterMillis)
        assertTrue(identity.isValidAt(identity.notBeforeMillis))
        assertTrue(identity.isValidAt(identity.notAfterMillis))
        assertFalse(identity.isValidAt(identity.notBeforeMillis - 1))
        assertFalse(identity.isValidAt(identity.notAfterMillis + 1))
    }

    @Test fun selfSignedCertificateRequiresExplicitReview() {
        val error = handshake(ReviewingTrustManager("", systemManager(trustServer = false)))
        val review = findReview(error)
        assertEquals(CertificateIdentity.from(certificate()), review.identity)
        assertEquals("", review.expectedSha256)
        assertNotNull(review.cause)
    }

    @Test fun trustedCertificateAndMatchingHostnameCompleteTls() {
        assertNull(handshake(ReviewingTrustManager("", systemManager(trustServer = true))))
    }

    @Test fun trustedCertificateWithWrongSanRequiresReview() {
        val error = handshake(ReviewingTrustManager("", systemManager(trustServer = true)),
            peerHost = "unmatched.example.invalid")
        val review = findReview(error)
        assertEquals(CertificateIdentity.from(certificate()), review.identity)
        assertEquals("", review.expectedSha256)
    }

    @Test fun exactPinAllowsSelfSignedCertificateAndReplacesHostnameTrust() {
        val pin = CertificateIdentity.from(certificate()).sha256
        // Exact leaf pin is the explicit trust basis even when the connection name differs.
        assertNull(handshake(ReviewingTrustManager(pin, systemManager(trustServer = false)),
            peerHost = "unmatched.example.invalid"))
    }

    @Test fun changedPinIsRejectedEvenWhenSystemTrustWouldPass() {
        val wrongPin = "00".repeat(32)
        val error = handshake(ReviewingTrustManager(wrongPin, systemManager(trustServer = true)))
        val review = findReview(error)
        assertEquals(wrongPin, review.expectedSha256)
        assertEquals(CertificateIdentity.from(certificate()), review.identity)
    }

    @Test fun expiredLeafCannotBeReviewedOrAcceptedByPin() {
        assertInvalidLeaf("expired", CertificateExpiredException::class.java)
    }

    @Test fun notYetValidLeafCannotBeReviewedOrAcceptedByPin() {
        assertInvalidLeaf("future", CertificateNotYetValidException::class.java)
    }

    @Test fun expiredLeafFailsRealTlsWithoutReview() {
        val pin = CertificateIdentity.from(certificate("expired")).sha256
        val error = handshake(ReviewingTrustManager(pin, systemManager(trustServer = false)),
            fixture = "expired")
        assertNotNull(error)
        assertTrue(causes(error).any { it is CertificateExpiredException })
        assertFalse(causes(error).any { it is CertificateReviewException })
    }

    @Test fun socketOverloadPreservesChainAuthTypeAndSocket() {
        val delegate = RecordingManager()
        val chain = arrayOf(certificate())
        Socket().use { socket ->
            ReviewingTrustManager("", delegate).checkServerTrusted(chain, "ECDHE_RSA", socket)
            assertEquals("server-socket", delegate.overload)
            assertSame(chain, delegate.chain)
            assertEquals("ECDHE_RSA", delegate.authType)
            assertSame(socket, delegate.socket)
        }
    }

    @Test fun engineOverloadPreservesChainAuthTypeAndEngine() {
        val delegate = RecordingManager()
        val chain = arrayOf(certificate())
        val engine = SSLContext.getDefault().createSSLEngine("localhost", 443)
        ReviewingTrustManager("", delegate).checkServerTrusted(chain, "RSA", engine)
        assertEquals("server-engine", delegate.overload)
        assertSame(chain, delegate.chain)
        assertEquals("RSA", delegate.authType)
        assertSame(engine, delegate.engine)
    }

    @Test fun contextFreeOverloadRemainsContextFree() {
        val delegate = RecordingManager()
        ReviewingTrustManager("", delegate).checkServerTrusted(arrayOf(certificate()), "RSA")
        assertEquals("server-basic", delegate.overload)
    }

    @Test fun clientOverloadsDelegateRatherThanApplyServerPins() {
        val delegate = RecordingManager()
        val manager = ReviewingTrustManager("00".repeat(32), delegate)
        val chain = arrayOf(certificate())
        manager.checkClientTrusted(chain, "RSA")
        assertEquals("client-basic", delegate.overload)
        Socket().use { socket ->
            manager.checkClientTrusted(chain, "RSA", socket)
            assertEquals("client-socket", delegate.overload)
            assertSame(socket, delegate.socket)
        }
        val engine = SSLContext.getDefault().createSSLEngine()
        manager.checkClientTrusted(chain, "RSA", engine)
        assertEquals("client-engine", delegate.overload)
        assertSame(engine, delegate.engine)
        assertArrayEquals(delegate.acceptedIssuers, manager.acceptedIssuers)
    }

    @Test fun expiredIntermediateCauseCannotBecomeReviewable() {
        val expired = CertificateExpiredException("test intermediate expired")
        val delegate = RecordingManager().also { it.failure = CertificateException("chain failed", expired) }
        val error = assertThrows(CertificateExpiredException::class.java) {
            ReviewingTrustManager("", delegate).checkServerTrusted(arrayOf(certificate()), "RSA")
        }
        assertSame(expired, error)
    }

    @Test fun notYetValidIntermediateCauseCannotBecomeReviewable() {
        val future = CertificateNotYetValidException("test intermediate not yet valid")
        val delegate = RecordingManager().also { it.failure = CertificateException("chain failed", future) }
        val error = assertThrows(CertificateNotYetValidException::class.java) {
            ReviewingTrustManager("", delegate).checkServerTrusted(arrayOf(certificate()), "RSA")
        }
        assertSame(future, error)
    }

    @Test fun certPathDateReasonCannotBecomeReviewable() {
        for (reason in listOf(CertPathValidatorException.BasicReason.EXPIRED,
            CertPathValidatorException.BasicReason.NOT_YET_VALID)) {
            val pathFailure = CertPathValidatorException("test validity error", null, null, -1, reason)
            val delegate = RecordingManager().also { it.failure = CertificateException("chain", pathFailure) }
            val error = assertThrows(CertificateException::class.java) {
                ReviewingTrustManager("", delegate).checkServerTrusted(arrayOf(certificate()), "RSA")
            }
            assertFalse(error is CertificateReviewException)
            assertTrue(error is CertificateExpiredException || error is CertificateNotYetValidException)
        }
    }

    @Test fun missingCertificateIsRejectedWithoutReview() {
        val manager = ReviewingTrustManager("", RecordingManager())
        for (chain in listOf(null, emptyArray<X509Certificate>())) {
            val error = assertThrows(CertificateException::class.java) { manager.checkServerTrusted(chain, "RSA") }
            assertFalse(error is CertificateReviewException)
        }
    }

    @Test fun unexpectedDelegateFailureIsNotConvertedToCertificateReview() {
        val delegate = RecordingManager().also { it.unexpected = IllegalStateException("provider error") }
        val error = assertThrows(IllegalStateException::class.java) {
            ReviewingTrustManager("", delegate).checkServerTrusted(arrayOf(certificate()), "RSA")
        }
        assertEquals("provider error", error.message)
    }

    @Test fun defaultTrustManagerIsAvailableAndDoesNotTrustTestCertificate() {
        findReview(handshake(ReviewingTrustManager("")))
    }

    private fun assertInvalidLeaf(fixture: String, type: Class<out CertificateException>) {
        val leaf = certificate(fixture)
        for (pin in listOf("", CertificateIdentity.from(leaf).sha256, "00".repeat(32))) {
            val delegate = RecordingManager()
            val error = assertThrows(type) {
                ReviewingTrustManager(pin, delegate).checkServerTrusted(arrayOf(leaf), "RSA")
            }
            assertFalse(error is CertificateReviewException)
            assertNull(delegate.overload)
        }
    }

    private fun fixture(name: String = "localhost"): KeyStore = KeyStore.getInstance("PKCS12").apply {
        val stream = ReviewingTrustManagerTest::class.java.getResourceAsStream("/tls/$name.p12")
            ?: error("Missing TLS test fixture $name")
        stream.use { load(it, "test-only".toCharArray()) }
    }

    private fun certificate(name: String = "localhost") =
        fixture(name).getCertificate("test-server") as X509Certificate

    private fun systemManager(trustServer: Boolean): X509ExtendedTrustManager {
        val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            // Keep an unrelated anchor: SunJSSE rejects a literally empty trust store
            // with a provider error rather than a normal CertificateException.
            setCertificateEntry("unrelated", certificate("future"))
            if (trustServer) setCertificateEntry("server", certificate())
        }
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(anchors)
        return factory.trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()
    }

    private fun handshake(manager: X509ExtendedTrustManager, peerHost: String = "localhost",
        fixture: String = "localhost"): Throwable? {
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(fixture(fixture), "test-only".toCharArray())
        }
        val serverContext = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        val server = serverContext.serverSocketFactory.createServerSocket(0, 1,
            InetAddress.getLoopbackAddress()) as SSLServerSocket
        server.soTimeout = 5_000
        val executor = Executors.newSingleThreadExecutor { Thread(it, "tls-test-server").apply { isDaemon = true } }
        val result = executor.submit<Boolean> {
            runCatching {
                (server.accept() as SSLSocket).use {
                    it.soTimeout = 5_000
                    it.enabledProtocols = arrayOf("TLSv1.2")
                    it.startHandshake()
                    true
                }
            }.getOrDefault(false)
        }
        try {
            val clientContext = SSLContext.getInstance("TLS").apply { init(null, arrayOf(manager), null) }
            val failure = Socket(InetAddress.getLoopbackAddress(), server.localPort).use { raw ->
                (clientContext.socketFactory.createSocket(raw, peerHost, server.localPort, true) as SSLSocket).use {
                    it.soTimeout = 5_000
                    it.enabledProtocols = arrayOf("TLSv1.2")
                    it.sslParameters = it.sslParameters.also { params -> params.endpointIdentificationAlgorithm = "HTTPS" }
                    try { it.startHandshake(); null } catch (error: SSLException) { error }
                }
            }
            val serverAccepted = result.get(6, TimeUnit.SECONDS)
            if (failure == null) assertTrue("Server must also complete TLS", serverAccepted)
            return failure
        } finally {
            server.close()
            result.cancel(true)
            executor.shutdownNow()
        }
    }

    private fun causes(error: Throwable?): List<Throwable> = generateSequence(error) { it.cause }.take(32).toList()
    private fun findReview(error: Throwable?): CertificateReviewException {
        assertNotNull("TLS must reject the certificate", error)
        return causes(error).filterIsInstance<CertificateReviewException>().firstOrNull()
            ?: throw AssertionError("Expected a reviewable certificate error", error)
    }

    private class RecordingManager : X509ExtendedTrustManager() {
        var overload: String? = null
        var chain: Array<out X509Certificate>? = null
        var authType: String? = null
        var socket: Socket? = null
        var engine: SSLEngine? = null
        var failure: CertificateException? = null
        var unexpected: RuntimeException? = null
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        private fun record(name: String, certificates: Array<out X509Certificate>?, auth: String?) {
            overload = name; chain = certificates; authType = auth
            unexpected?.let { throw it }
            failure?.let { throw it }
        }
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            record("server-basic", chain, authType)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
            this.socket = socket; record("server-socket", chain, authType)
        }
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
            this.engine = engine; record("server-engine", chain, authType)
        }
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            record("client-basic", chain, authType)
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
            this.socket = socket; record("client-socket", chain, authType)
        }
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
            this.engine = engine; record("client-engine", chain, authType)
        }
    }
}
