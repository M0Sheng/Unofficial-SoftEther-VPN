package kittoku.mvc.nativecore

import kittoku.mvc.cipher.hashSha0
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeRemoteManagementPasswordTest {
    @Test fun matchesOfficialAsciiSha0VectorAndReturnsRaw20Bytes() {
        val password = "abcdefghijkl".toCharArray()
        val hash = NativeRemoteManagementPassword.hash(password)
        assertEquals(20, hash.size)
        // Independent vector generated from the pinned official Encrypt.c MY_SHA0.
        assertEquals("46ec20a71c8d17d44ff61b590205f466a58081aa", hash.joinToString("") { "%02x".format(it.toInt() and 255) })
        assertEquals("abcdefghijkl", password.concatToString())
        assertTrue(NativeRemoteManagementPassword.isUsableHash(hash))
    }

    @Test fun acceptsOnlyTheDocumentedLengthAndAsciiRange() {
        assertTrue(NativeRemoteManagementPassword.isValid(CharArray(12) { '!' }))
        assertTrue(NativeRemoteManagementPassword.isValid(CharArray(128) { '~' }))
        for (password in listOf(CharArray(11) { 'A' }, CharArray(129) { 'A' },
            "abcdefghijk ".toCharArray(), "abcdefghijk\n".toCharArray(), "abcdefghijké".toCharArray())) {
            assertFalse(NativeRemoteManagementPassword.isValid(password))
            assertThrows(IllegalArgumentException::class.java) { NativeRemoteManagementPassword.hash(password) }
        }
    }

    @Test fun rejectsTruncatedTextEncodedZeroAndEmptyPasswordHashes() {
        assertFalse(NativeRemoteManagementPassword.isUsableHash(ByteArray(19) { 1 }))
        assertFalse(NativeRemoteManagementPassword.isUsableHash(ByteArray(21) { 1 }))
        assertFalse(NativeRemoteManagementPassword.isUsableHash(ByteArray(20)))
        assertFalse(NativeRemoteManagementPassword.isUsableHash("0123456789012345678901234567890123456789".toByteArray()))
        assertFalse(NativeRemoteManagementPassword.isUsableHash(hashSha0(ByteArray(0))))
    }
}
