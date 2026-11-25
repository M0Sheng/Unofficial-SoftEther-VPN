package kittoku.mvc.nativecore

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.nativecore.NativeCoreRunner.Companion.token
import kittoku.mvc.tls.ClientKeyProtection
import java.io.File
import java.io.IOException
import java.nio.CharBuffer
import java.nio.charset.Charset
import java.nio.file.Files
import java.util.Base64
import java.util.HexFormat

internal enum class NativeAuthMode {
    ANONYMOUS, STANDARD_PASSWORD, EXTERNAL_PASSWORD, CLIENT_CERTIFICATE;

    val usesPassword: Boolean get() = this == STANDARD_PASSWORD || this == EXTERNAL_PASSWORD

    companion object {
        fun from(raw: String?): NativeAuthMode = if (raw.isNullOrEmpty()) STANDARD_PASSWORD else valueOf(raw)
    }
}

internal class NativeAuthentication(
    val mode: NativeAuthMode,
    val password: String,
    private val passwordEncoding: String,
    private val certificate: String,
    private val protectedKey: String,
) {
    val diagnosticSummary: String
        get() = if (mode.usesPassword) {
            "auth_method=${mode.name} password_encoding=$passwordEncoding credential_present=${password.isNotEmpty()}"
        } else "auth_method=${mode.name}"

    fun validate() {
        if (mode.usesPassword) {
            require(password.none { it == '\n' || it == '\r' || it == '\u0000' }) { appText(R.string.network_runtime_error_password_invalid_characters) }
            require(Charset.forName(passwordEncoding).newEncoder().canEncode(password)) {
                appText(R.string.network_runtime_error_password_encoding_invalid)
            }
            if (mode == NativeAuthMode.EXTERNAL_PASSWORD) {
                // The native plain-password account field is limited to 255 UTF-8 bytes.
                val bytes = password.toByteArray(Charsets.UTF_8)
                try { require(bytes.size <= 255) { appText(R.string.network_runtime_error_domain_password_too_long) } }
                finally { bytes.fill(0) }
            }
        }
        if (mode == NativeAuthMode.CLIENT_CERTIFICATE) {
            require(certificate.isNotBlank() && protectedKey.isNotBlank()) { appText(R.string.network_runtime_error_missing_client_certificate_key) }
        }
    }

    fun provision(directory: File, writePrivate: (File, ByteArray) -> Unit, runCommand: (String) -> Unit) {
        when (mode) {
            NativeAuthMode.ANONYMOUS -> runCommand("AccountAnonymousSet home")
            NativeAuthMode.STANDARD_PASSWORD -> provisionStandardPassword(runCommand)
            NativeAuthMode.EXTERNAL_PASSWORD -> runCommand("AccountPasswordSet home /PASSWORD:${token(password)} /TYPE:radius")
            NativeAuthMode.CLIENT_CERTIFICATE -> provisionCertificate(directory, writePrivate, runCommand)
        }
    }

    private fun provisionStandardPassword(runCommand: (String) -> Unit) {
        if (passwordEncoding != "GBK" || password.isEmpty()) {
            runCommand("AccountPasswordSet home /PASSWORD:${token(password)} /TYPE:standard")
            return
        }
        val encoded = Charset.forName("GBK").newEncoder().encode(CharBuffer.wrap(password))
        val bytes = ByteArray(encoded.remaining()).also { encoded.get(it) }
        try {
            runCommand("AccountPasswordSet home /PASSWORD:${token(HexFormat.of().withUpperCase().formatHex(bytes))} /TYPE:standard-hex")
        } finally {
            bytes.fill(0)
            if (encoded.hasArray()) encoded.array().fill(0)
        }
    }

    private fun provisionCertificate(directory: File, writePrivate: (File, ByteArray) -> Unit, runCommand: (String) -> Unit) {
        val certificateDer = runCatching { Base64.getDecoder().decode(certificate) }.getOrElse {
            throw IllegalArgumentException(appText(R.string.network_runtime_error_invalid_client_certificate))
        }
        val keyDer = runCatching { ClientKeyProtection.decrypt(protectedKey) }.getOrElse {
            throw IllegalArgumentException(appText(R.string.network_runtime_error_client_key_unreadable))
        }
        var credentials: File? = null
        var certificateFile: File? = null
        var keyFile: File? = null
        try {
            val staging = Files.createTempDirectory(directory.toPath(), "client-credentials-").toFile()
            credentials = staging
            certificateFile = File(staging, "client.cer")
            keyFile = File(staging, "client.key")
            writePrivate(certificateFile, certificateDer)
            writePrivate(keyFile, keyDer)
            runCommand("AccountCertSet home /LOADCERT:${token(certificateFile.path)} /LOADKEY:${token(keyFile.path)}")
        } finally {
            keyDer.fill(0)
            val keyRemoved = keyFile == null || !keyFile.exists() || keyFile.delete()
            certificateFile?.delete()
            credentials?.delete()
            if (!keyRemoved) throw IOException(appText(R.string.network_runtime_error_client_key_temporary_file))
        }
    }

    companion object {
        fun from(mode: NativeAuthMode, password: String, passwordEncoding: String, values: (String) -> String): NativeAuthentication =
            if (mode == NativeAuthMode.CLIENT_CERTIFICATE) {
                NativeAuthentication(mode, password, passwordEncoding, values("HOME_CLIENT_CERT"), values("HOME_CLIENT_KEY"))
            } else NativeAuthentication(mode, password, passwordEncoding, "", "")
    }
}
