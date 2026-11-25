package kittoku.mvc.tls

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Encrypt client private keys before they enter the profile registry. */
internal object ClientKeyProtection {
    private const val ALIAS = "softether_client_credentials_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    fun encrypt(der: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(create = true))
        check(cipher.iv.size == IV_BYTES)
        return Base64.getEncoder().encodeToString(cipher.iv + cipher.doFinal(der))
    }

    fun decrypt(encoded: String): ByteArray {
        require(encoded.length in 1..ClientCertificateFiles.MAX_FILE_BYTES)
        val data = Base64.getDecoder().decode(encoded)
        require(data.size > IV_BYTES + TAG_BITS / 8)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(create = false), GCMParameterSpec(TAG_BITS, data, 0, IV_BYTES))
        return cipher.doFinal(data, IV_BYTES, data.size - IV_BYTES)
    }

    @Synchronized
    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        check(create) { appText(R.string.profile_runtime_client_key_protection_unavailable) }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build())
            generateKey()
        }
    }
}
