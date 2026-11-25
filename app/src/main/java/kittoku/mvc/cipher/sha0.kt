package kittoku.mvc.cipher

import java.nio.ByteBuffer

private const val SHA_BLOCK_BYTES = 64
private const val SHA_BLOCK_WORDS = SHA_BLOCK_BYTES / Int.SIZE_BYTES

/**
 * Original SHA from NIST FIPS 180 (1993), for SoftEther wire compatibility.
 * https://csrc.nist.gov/pubs/fips/180/final
 */
internal fun hashSha0(input: ByteArray): ByteArray {
    val state = intArrayOf(
        0x67452301,
        0xefcdab89.toInt(),
        0x98badcfe.toInt(),
        0x10325476,
        0xc3d2e1f0.toInt(),
    )
    val schedule = IntArray(SHA_BLOCK_WORDS)
    val message = ByteBuffer.wrap(input)
    val tail = ByteBuffer.allocate(SHA_BLOCK_BYTES)

    try {
        while (message.remaining() >= SHA_BLOCK_BYTES) {
            compressSha0(message, state, schedule)
        }

        tail.put(message)
        tail.put(0x80.toByte())
        if (tail.remaining() < Long.SIZE_BYTES) {
            tail.rewind()
            compressSha0(tail, state, schedule)
            tail.array().fill(0)
        }

        tail.putLong(SHA_BLOCK_BYTES - Long.SIZE_BYTES, input.size.toLong() * Byte.SIZE_BITS)
        tail.rewind()
        compressSha0(tail, state, schedule)

        val digest = ByteBuffer.allocate(state.size * Int.SIZE_BYTES)
        for (word in state) digest.putInt(word)
        return digest.array()
    } finally {
        tail.array().fill(0)
        schedule.fill(0)
        state.fill(0)
    }
}

/** FIPS 180 section 8 uses a circular message schedule of sixteen words. */
private fun compressSha0(block: ByteBuffer, state: IntArray, schedule: IntArray) {
    for (slot in schedule.indices) schedule[slot] = block.int

    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    val mask = SHA_BLOCK_WORDS - 1

    for (round in 0 until 80) {
        val slot = round and mask
        if (round >= SHA_BLOCK_WORDS) {
            schedule[slot] = schedule[(round - 3) and mask] xor schedule[(round - 8) and mask] xor
                schedule[(round - 14) and mask] xor schedule[slot]
        }

        val mix: Int
        val constant: Int
        when (round / 20) {
            0 -> {
                mix = (b and c) or (b.inv() and d)
                constant = 0x5a827999
            }
            1 -> {
                mix = b xor c xor d
                constant = 0x6ed9eba1
            }
            2 -> {
                mix = (b and c) or (b and d) or (c and d)
                constant = 0x8f1bbcdc.toInt()
            }
            else -> {
                mix = b xor c xor d
                constant = 0xca62c1d6.toInt()
            }
        }

        // Int addition implements the standard's arithmetic modulo 2^32.
        val next = a.rotateLeft(5) + mix + e + schedule[slot] + constant
        e = d
        d = c
        c = b.rotateLeft(30)
        b = a
        a = next
    }

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
}
