package kittoku.mvc.nativecore

import kittoku.mvc.tls.ClientCertificateFiles
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.util.Base64

class NativeAuthenticationTest {
    @Test fun legacyProfilesStillUseStandardPassword() {
        assertEquals(NativeAuthMode.STANDARD_PASSWORD, NativeAuthMode.from(null))
        assertEquals(NativeAuthMode.STANDARD_PASSWORD, NativeAuthMode.from(""))
        assertThrows(IllegalArgumentException::class.java) { NativeAuthMode.from("SMART_CARD") }
    }

    @Test fun anonymousDoesNotSubmitCredentialsAndRadiusUsesPlainPasswordMode() {
        assertEquals("AccountAnonymousSet home", command(NativeAuthMode.ANONYMOUS, "unused"))
        assertEquals("AccountPasswordSet home /PASSWORD:\"pass word\" /TYPE:radius",
            command(NativeAuthMode.EXTERNAL_PASSWORD, "pass word"))
    }

    @Test fun standardPasswordPreservesUtf8AndGbkRepresentations() {
        assertEquals("AccountPasswordSet home /PASSWORD:\"密码\" /TYPE:standard",
            command(NativeAuthMode.STANDARD_PASSWORD, "密码"))
        assertEquals("AccountPasswordSet home /PASSWORD:\"C3DCC2EB\" /TYPE:standard-hex",
            command(NativeAuthMode.STANDARD_PASSWORD, "密码", "GBK"))
    }

    @Test fun externalPasswordCannotBeTruncatedByTheNativeAccount() {
        command(NativeAuthMode.EXTERNAL_PASSWORD, "a".repeat(255))
        assertThrows(IllegalArgumentException::class.java) { command(NativeAuthMode.EXTERNAL_PASSWORD, "密".repeat(86)) }
    }

    @Test fun readsRsaPrivateKeysFromDerAndPem() {
        val key = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().private as RSAPrivateKey
        val der = key.encoded
        val base64 = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(der)
        val pem = "-----BEGIN PRIVATE KEY-----\n$base64\n-----END PRIVATE KEY-----\n".toByteArray()
        assertEquals(key.modulus, ClientCertificateFiles.privateKey(der).modulus)
        assertEquals(key.modulus, ClientCertificateFiles.privateKey(pem).modulus)
        assertThrows(IllegalArgumentException::class.java) {
            ClientCertificateFiles.privateKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\n$base64\n-----END ENCRYPTED PRIVATE KEY-----".toByteArray())
        }
    }

    private fun command(mode: NativeAuthMode, password: String, encoding: String = "UTF-8"): String {
        val authentication = NativeAuthentication.from(mode, password, encoding) { error("Unexpected certificate read") }
        authentication.validate()
        val commands = mutableListOf<String>()
        authentication.provision(File("unused"), { _, _ -> error("Unexpected credential file") }) { commands += it }
        return commands.single()
    }
}
