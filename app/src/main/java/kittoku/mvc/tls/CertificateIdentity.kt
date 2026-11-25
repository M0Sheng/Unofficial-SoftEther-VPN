package kittoku.mvc.tls

import java.security.MessageDigest
import java.security.cert.X509Certificate

/** Unverified certificate details for display; the subject/issuer are not proof of identity. */
data class CertificateIdentity(
    val sha256: String,
    val subject: String,
    val issuer: String,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
    val alternativeNames: String
) {
    fun isValidAt(nowMillis: Long): Boolean =
        nowMillis >= notBeforeMillis && nowMillis <= notAfterMillis

    companion object {
        fun from(certificate: X509Certificate): CertificateIdentity {
            val digest = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            val names = certificate.subjectAlternativeNames.orEmpty().mapNotNull { entry ->
                val type = entry.getOrNull(0) as? Int
                val value = entry.getOrNull(1) as? String ?: return@mapNotNull null
                when (type) {
                    2 -> "DNS:$value"
                    7 -> "IP:$value"
                    else -> null
                }
            }.joinToString(", ")
            return CertificateIdentity(
                sha256 = digest,
                subject = certificate.subjectX500Principal.name,
                issuer = certificate.issuerX500Principal.name,
                notBeforeMillis = certificate.notBefore.time,
                notAfterMillis = certificate.notAfter.time,
                alternativeNames = names
            )
        }
    }
}
