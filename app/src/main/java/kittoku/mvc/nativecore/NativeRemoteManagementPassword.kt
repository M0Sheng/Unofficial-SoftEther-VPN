package kittoku.mvc.nativecore

import java.security.MessageDigest
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.cipher.hashSha0

/** Official client-management compatibility hash, not a VPN account password hash. */
internal object NativeRemoteManagementPassword {
    private val emptyPasswordHash = hashSha0(ByteArray(0))
    fun isValid(password: CharArray): Boolean = password.size in 12..128 && password.all { it.code in 0x21..0x7e }

    fun isUsableHash(hash: ByteArray): Boolean = hash.size == 20 &&
        hash.any { it != 0.toByte() } && !MessageDigest.isEqual(hash, emptyPasswordHash)

    fun hash(password: CharArray): ByteArray {
        require(isValid(password)) { appText(R.string.network_runtime_error_remote_password_shape) }
        val ascii = ByteArray(password.size) { password[it].code.toByte() }
        return try { hashSha0(ascii) }
        finally { ascii.fill(0) }
    }
}
