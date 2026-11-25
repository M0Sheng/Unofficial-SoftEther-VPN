package kittoku.mvc.tls

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.IdentityHashMap
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager

class CertificateReviewException(
    val identity: CertificateIdentity,
    val expectedSha256: String,
    cause: Throwable
) : CertificateException(
    if (expectedSha256.isEmpty()) appText(R.string.profile_runtime_untrusted_server_certificate)
    else appText(R.string.profile_runtime_changed_server_fingerprint),
    cause
)

/**
 * Never approves an unknown certificate. The caller must stop the connection and
 * obtain explicit approval before retrying with the displayed certificate's hash.
 *
 * A non-empty pin deliberately replaces CA/hostname trust with exact leaf trust.
 * The socket must still perform TLS proof-of-key, and validity is checked on each call.
 */
class ReviewingTrustManager(
    val expectedSha256: String,
    private val delegate: X509ExtendedTrustManager = defaultTrustManager()
) : X509ExtendedTrustManager() {
    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
        delegate.checkClientTrusted(chain, authType)

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) =
        delegate.checkClientTrusted(chain, authType, socket)

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) =
        delegate.checkClientTrusted(chain, authType, engine)

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) =
        reviewServer(chain) { delegate.checkServerTrusted(chain, authType) }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) =
        reviewServer(chain) { delegate.checkServerTrusted(chain, authType, socket) }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) =
        reviewServer(chain) { delegate.checkServerTrusted(chain, authType, engine) }

    private inline fun reviewServer(chain: Array<out X509Certificate>?, verify: () -> Unit) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException(appText(R.string.profile_runtime_missing_server_certificate))
        // Keep this outside the wrapping catch: invalid dates cannot be approved.
        leaf.checkValidity()
        val identity = CertificateIdentity.from(leaf)
        if (expectedSha256.isNotEmpty()) {
            if (identity.sha256 != expectedSha256) {
                throw CertificateReviewException(identity, expectedSha256,
                    CertificateException(appText(R.string.profile_runtime_server_fingerprint_mismatch)))
            }
            return
        }
        try {
            verify()
        } catch (error: CertificateException) {
            // A valid leaf must not hide an expired intermediate or other date failure.
            findValidityFailure(error)?.let { throw it }
            throw CertificateReviewException(identity, expectedSha256, error)
        }
    }
}

private fun defaultTrustManager(): X509ExtendedTrustManager {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(null as KeyStore?)
    return factory.trustManagers.filterIsInstance<X509ExtendedTrustManager>().firstOrNull()
        ?: throw IllegalStateException(appText(R.string.profile_runtime_tls_no_hostname_verifier))
}

private fun findValidityFailure(error: Throwable): CertificateException? {
    val visited = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
    var current: Throwable? = error
    while (current != null && visited.add(current)) {
        when (current) {
            is CertificateExpiredException -> return current
            is CertificateNotYetValidException -> return current
            is CertPathValidatorException -> when (current.reason) {
                CertPathValidatorException.BasicReason.EXPIRED ->
                    return CertificateExpiredException(current.message).also { it.initCause(error) }
                CertPathValidatorException.BasicReason.NOT_YET_VALID ->
                    return CertificateNotYetValidException(current.message).also { it.initCause(error) }
                else -> Unit
            }
        }
        current = current.cause
    }
    return null
}
