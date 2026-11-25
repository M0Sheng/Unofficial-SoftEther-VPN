package kittoku.mvc.tls

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

internal object ClientCertificateFiles {
    const val MAX_FILE_BYTES = 16 * 1024
    private val supportedSizes = setOf(1024, 1536, 2048, 3072, 4096)
    private val pkcs8RsaHeader = byteArrayOf(2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0)

    fun certificate(input: ByteArray): X509Certificate {
        require(input.size in 1..MAX_FILE_BYTES)
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(input)) as X509Certificate
        val key = certificate.publicKey as? RSAPublicKey ?: error(appText(R.string.profile_runtime_client_certificate_requires_rsa))
        require(key.modulus.bitLength() in supportedSizes)
        return certificate
    }

    fun privateKey(input: ByteArray): RSAPrivateKey {
        require(input.size in 1..MAX_FILE_BYTES)
        val encoded = if (input[0] == '-'.code.toByte()) {
            val text = input.toString(Charsets.US_ASCII).trim()
            val type = if (text.startsWith("-----BEGIN RSA PRIVATE KEY-----")) "RSA PRIVATE KEY" else "PRIVATE KEY"
            val header = "-----BEGIN $type-----"
            val footer = "-----END $type-----"
            require(text.startsWith(header) && text.endsWith(footer))
            val body = text.removePrefix(header).removeSuffix(footer).filterNot(Char::isWhitespace)
            val decoded = Base64.getDecoder().decode(body)
            if (type == "RSA PRIVATE KEY") {
                try { derObject(48, pkcs8RsaHeader + derObject(4, decoded)) } finally { decoded.fill(0) }
            } else decoded
        } else input
        try {
            val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(encoded)) as RSAPrivateKey
            require(key.modulus.bitLength() in supportedSizes)
            return key
        } finally {
            if (encoded !== input) encoded.fill(0)
        }
    }

    fun matches(certificateDer: ByteArray, key: ByteArray): Boolean {
        val publicKey = certificate(certificateDer).publicKey as RSAPublicKey
        return publicKey.modulus == privateKey(key).modulus
    }

    private fun derObject(tag: Byte, body: ByteArray): ByteArray {
        val length = when {
            body.size < 128 -> byteArrayOf(body.size.toByte())
            body.size < 256 -> byteArrayOf(-127, body.size.toByte())
            else -> byteArrayOf(-126, (body.size shr 8).toByte(), body.size.toByte())
        }
        return byteArrayOf(tag) + length + body
    }
}
