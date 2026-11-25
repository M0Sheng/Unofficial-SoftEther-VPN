package kittoku.mvc.tls

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

/** Versioned private metadata. Missing profile IDs, truncated and oversized records fail closed. */
internal object CertificateApprovalCodec {
    private const val PREFIX = "profile-v1:"
    private const val MAX_ENCODED = 96 * 1024
    private const val MAX_FIELD = 8192
    private val PIN = Regex("[0-9a-f]{64}")

    fun encode(value: CertificateApproval): String {
        validate(value)
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { output ->
            with(output) {
                writeUTF(value.requestId); writeUTF(value.profileId)
                writeUTF(value.endpoint.host); writeInt(value.endpoint.port)
                writeUTF(value.backendMode); writeUTF(value.expectedSha256); writeLong(value.createdAtMillis)
                writeUTF(value.identity.sha256); writeUTF(value.identity.subject); writeUTF(value.identity.issuer)
                writeLong(value.identity.notBeforeMillis); writeLong(value.identity.notAfterMillis)
                writeUTF(value.identity.alternativeNames)
            }
        }
        return (PREFIX + Base64.getEncoder().encodeToString(buffer.toByteArray())).also { require(it.length <= MAX_ENCODED) }
    }

    fun decode(encoded: String): CertificateApproval {
        require(encoded.startsWith(PREFIX) && encoded.length <= MAX_ENCODED) { appText(R.string.profile_runtime_invalid_certificate_approval) }
        val data = Base64.getDecoder().decode(encoded.removePrefix(PREFIX))
        return DataInputStream(ByteArrayInputStream(data)).use { input ->
            with(input) {
                val id = readUTF(); val profile = readUTF()
                val endpoint = CertificateEndpoint.of(readUTF(), readInt())
                val backend = readUTF(); val previous = readUTF(); val created = readLong()
                val identity = CertificateIdentity(readUTF(), readUTF(), readUTF(), readLong(), readLong(), readUTF())
                require(available() == 0) { appText(R.string.profile_runtime_unexpected_certificate_approval_data) }
                CertificateApproval(id, profile, endpoint, backend, previous, identity, created).also(::validate)
            }
        }
    }

    private fun validate(value: CertificateApproval) {
        CertificateProfileScope.prefix(value.profileId)
        require(value.requestId.isNotBlank() && value.requestId.length <= 128)
        require(value.backendMode in setOf("ROOT_NATIVE", "TUN"))
        require(value.expectedSha256.isEmpty() || value.expectedSha256.matches(PIN))
        require(value.identity.sha256.matches(PIN))
        require(listOf(value.endpoint.host, value.identity.subject, value.identity.issuer, value.identity.alternativeNames)
            .all { it.length <= MAX_FIELD })
        require(value.identity.notBeforeMillis <= value.identity.notAfterMillis)
    }
}
