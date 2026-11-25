package kittoku.mvc.tls

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.security.MessageDigest
import java.util.Locale

/** A TLS peer is identified by its configured host and port, rather than its resolved IP. */
@ConsistentCopyVisibility
data class CertificateEndpoint private constructor(val host: String, val port: Int) {
    val key: String = MessageDigest.getInstance("SHA-256")
        .digest("$host\n$port".toByteArray(Charsets.UTF_8))
        .joinToString("") { byte ->
            val value = byte.toInt() and 0xff
            "0123456789abcdef"[value ushr 4].toString() + "0123456789abcdef"[value and 0x0f]
        }

    companion object {
        fun of(host: String, port: Int): CertificateEndpoint {
            val normalizedHost = host.trim().removeSurrounding("[", "]").lowercase(Locale.ROOT)
            require(normalizedHost.isNotEmpty()) { appText(R.string.profile_runtime_missing_certificate_host) }
            require(port in 1..65535) { appText(R.string.profile_runtime_invalid_certificate_port) }
            return CertificateEndpoint(normalizedHost, port)
        }
    }
}

/** Immutable snapshot of the exact trust decision shown to the user. */
data class CertificateApproval(
    val requestId: String,
    val profileId: String,
    val endpoint: CertificateEndpoint,
    val backendMode: String,
    val expectedSha256: String,
    val identity: CertificateIdentity,
    val createdAtMillis: Long,
) {
    fun canAccept(
        requestId: String,
        currentProfileId: String,
        currentEndpoint: CertificateEndpoint,
        currentBackendMode: String,
        currentSavedSha256: String,
        nowMillis: Long,
    ): Boolean {
        if (profileId.isBlank() || requestId != this.requestId || currentProfileId != profileId ||
            currentEndpoint != endpoint || currentBackendMode != backendMode) {
            return false
        }
        if (currentSavedSha256 != expectedSha256) {
            return false
        }
        // Check ordering before subtraction so clock rollback and Long overflow cannot revive a request.
        if (nowMillis < createdAtMillis || nowMillis - createdAtMillis !in 0L..MAX_AGE_MILLIS) {
            return false
        }
        return identity.isValidAt(nowMillis)
    }

    private companion object {
        const val MAX_AGE_MILLIS = 10 * 60 * 1000L
    }
}

/** Only the namespace is hashed: the trust value still identifies the exact TLS leaf. */
internal object CertificateProfileScope {
    fun prefix(profileId: String): String {
        require(profileId.isNotBlank() && profileId.length <= 128 && profileId.none { it.isISOControl() }) {
            appText(R.string.profile_runtime_invalid_certificate_profile_id)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(profileId.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }
        return "trusted_profile_${digest}_"
    }

    fun key(profileId: String, endpoint: CertificateEndpoint): String = prefix(profileId) + endpoint.key
}
