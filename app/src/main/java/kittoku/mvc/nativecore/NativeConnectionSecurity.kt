package kittoku.mvc.nativecore

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.HexFormat

internal data class NativeConnectionSecurity(
    val tlsVersion: String?,
    val cipherSuite: String?,
    val encryptionEnabled: Boolean?,
    val serverCertificate: NativeServerCertificate?,
    val verification: NativeCertificateVerification,
)

internal data class NativeServerCertificate(
    val subject: String,
    val issuer: String,
    val expiresAtMillis: Long,
    val sha1: String,
    val sha256: String,
)

internal enum class NativeCertificateVerification { SYSTEM_CA, SAVED_PIN, NATIVE_VERIFIED, UNVERIFIED, UNKNOWN }

/** Reads only established-session fields reported by the native daemon through vpncmd. */
internal class NativeConnectionSecurityReader(verifiedLeafPem: ByteArray? = null, profilePin: String = "") {
    private val verifiedLeafSha256 = verifiedLeafPem?.let { pem ->
        runCatching { fingerprint(parseCertificate(pem).encoded, "SHA-256") }.getOrNull()
    }
    private val preflightVerification = when {
        profilePin.isEmpty() -> NativeCertificateVerification.SYSTEM_CA
        profilePin == verifiedLeafSha256 -> NativeCertificateVerification.SAVED_PIN
        else -> NativeCertificateVerification.NATIVE_VERIFIED
    }
    private var cachedDer: String? = null
    private var cachedCertificate: NativeServerCertificate? = null

    fun read(rows: Map<String, String>): NativeConnectionSecurity? {
        if (nativeAccountPhase(rows["Session Status"]) != "established") return null
        val tlsVersion = rows["TLS Version"]?.takeIf(TLS_VERSION::matches)
        val cipher = rows["TLS Cipher Suite"]?.takeIf(CIPHER_NAME::matches)
        val encryption = binaryFlag(rows["VPN Payload Encryption"])
        val certificate = readCertificate(rows["Server Certificate DER"])
        val verification = when (binaryFlag(rows["Server Certificate Verified"])) {
            true -> {
                if (certificate != null && certificate.sha256 == verifiedLeafSha256) preflightVerification
                else NativeCertificateVerification.NATIVE_VERIFIED
            }
            false -> NativeCertificateVerification.UNVERIFIED
            null -> NativeCertificateVerification.UNKNOWN
        }
        if (tlsVersion == null && cipher == null && encryption == null && certificate == null &&
            verification == NativeCertificateVerification.UNKNOWN) return null
        return NativeConnectionSecurity(tlsVersion, cipher, encryption, certificate, verification)
    }

    private fun readCertificate(encoded: String?): NativeServerCertificate? {
        val bounded = encoded?.takeIf { it.length in 1..MAX_ENCODED_CERT_BYTES }
        if (bounded == cachedDer) return cachedCertificate
        cachedDer = bounded
        cachedCertificate = bounded?.let {
            runCatching {
                val der = Base64.getDecoder().decode(it)
                val certificate = parseCertificate(der)
                // The wire row must contain one exact DER leaf, without a second cert or suffix.
                require(der.contentEquals(certificate.encoded))
                NativeServerCertificate(
                    displayName(certificate.subjectX500Principal.name), displayName(certificate.issuerX500Principal.name),
                    certificate.notAfter.time, fingerprint(der, "SHA-1"), fingerprint(der, "SHA-256"),
                )
            }.getOrNull()
        }
        return cachedCertificate
    }

    private companion object {
        const val MAX_ENCODED_CERT_BYTES = (16 * 1024 + 2) / 3 * 4
        val TLS_VERSION = Regex("(?:TLSv|SSLv)[0-9]+(?:\\.[0-9]+)?")
        val CIPHER_NAME = Regex("[A-Za-z0-9_+-]{1,96}")

        fun binaryFlag(value: String?): Boolean? = when (value) {
            "1" -> true
            "0" -> false
            else -> null
        }

        fun parseCertificate(bytes: ByteArray): X509Certificate = ByteArrayInputStream(bytes).use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
        }

        fun displayName(name: String): String = buildString(name.length) {
            name.forEach {
                when (it.category) {
                    CharCategory.CONTROL, CharCategory.FORMAT, CharCategory.LINE_SEPARATOR, CharCategory.PARAGRAPH_SEPARATOR -> append(' ')
                    else -> append(it)
                }
            }
        }

        fun fingerprint(der: ByteArray, algorithm: String): String =
            HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(der))
    }
}
