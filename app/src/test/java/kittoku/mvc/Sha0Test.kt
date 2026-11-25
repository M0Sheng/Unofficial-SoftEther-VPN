package kittoku.mvc

import kittoku.mvc.cipher.hashSha0
import org.junit.Assert.assertEquals
import org.junit.Test

class Sha0Test {
    private fun digest(input: ByteArray): String = hashSha0(input).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    @Test fun standardSha0Vectors() {
        assertEquals("f96cea198ad1dd5617ac084a3d92c6107708c0ef", digest(byteArrayOf()))
        assertEquals("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", digest("abc".toByteArray(Charsets.US_ASCII)))
        assertEquals(
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8",
            digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toByteArray(Charsets.US_ASCII)),
        )
    }

    @Test fun paddingBoundaryVectorsAcrossOneAndTwoBlocks() {
        // Independently computed with byte-oriented SHA-0 padding, matching the
        // MY_SHA0_final reference in SoftEther src/Mayaqua/Encrypt.c. In
        // particular, lengths 55 and 119 fit the length field into their final
        // block and must not add a further block.
        val vectors = mapOf(
            54 to "38351a9ea6bcedb9bf4b48067f0bcdb5c4efcda8",
            55 to "0ff59f7cb9afc10d7abcdc9ab8c00e0e7b02034f",
            56 to "f826f1db56ddb270e25f21a7a40c4163b51c47ff",
            63 to "61191abbfdb5d1c77bceae556de82b39bfbfcb9a",
            64 to "6381391134b901db7a5a03699339bca31c409dde",
            65 to "b15055fc266b84dbb9f453a96d136bf3376cddeb",
            118 to "ce5aa236279e7f9766182e9557e12d2fd9c1e379",
            119 to "86683a324cedc63bef20d6425cb1680e4054cf57",
            120 to "451fa4e832121c06da75b5a4d4bcf705a1deec9c",
        )
        vectors.forEach { (length, expected) ->
            assertEquals("SHA-0 padding at $length bytes", expected, digest(ByteArray(length) { 'a'.code.toByte() }))
        }
    }

    @Test fun fips180LongMessageVector() {
        assertEquals(
            "3232affa48628a26653b5aaa44541fd90d690603",
            digest(ByteArray(1_000_000) { 'a'.code.toByte() }),
        )
    }
}
