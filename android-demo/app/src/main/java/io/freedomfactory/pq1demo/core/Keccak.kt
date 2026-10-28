package io.freedomfactory.pq1demo.core

/** Keccak-256 (the Ethereum variant: original 0x01 padding, not SHA3-256's 0x06). */
object Keccak {
    private val RC = longArrayOf(
        0x0000000000000001uL.toLong(), 0x0000000000008082uL.toLong(),
        0x800000000000808AuL.toLong(), 0x8000000080008000uL.toLong(),
        0x000000000000808BuL.toLong(), 0x0000000080000001uL.toLong(),
        0x8000000080008081uL.toLong(), 0x8000000000008009uL.toLong(),
        0x000000000000008AuL.toLong(), 0x0000000000000088uL.toLong(),
        0x0000000080008009uL.toLong(), 0x000000008000000AuL.toLong(),
        0x000000008000808BuL.toLong(), 0x800000000000008BuL.toLong(),
        0x8000000000008089uL.toLong(), 0x8000000000008003uL.toLong(),
        0x8000000000008002uL.toLong(), 0x8000000000000080uL.toLong(),
        0x000000000000800AuL.toLong(), 0x800000008000000AuL.toLong(),
        0x8000000080008081uL.toLong(), 0x8000000000008080uL.toLong(),
        0x0000000080000001uL.toLong(), 0x8000000080008008uL.toLong(),
    )

    // Rotation offsets indexed by x + 5y.
    private val R = intArrayOf(
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    )

    private const val RATE = 136

    fun hash256(input: ByteArray): ByteArray {
        val padLen = RATE - input.size % RATE
        val msg = input.copyOf(input.size + padLen)
        msg[input.size] = (msg[input.size].toInt() xor 0x01).toByte()
        msg[msg.size - 1] = (msg[msg.size - 1].toInt() xor 0x80).toByte()

        val s = LongArray(25)
        for (off in msg.indices step RATE) {
            for (i in 0 until RATE / 8) s[i] = s[i] xor readLe(msg, off + 8 * i)
            permute(s)
        }
        val out = ByteArray(32)
        for (i in 0 until 4) for (j in 0 until 8) out[8 * i + j] = (s[i] ushr (8 * j)).toByte()
        return out
    }

    private fun readLe(b: ByteArray, off: Int): Long {
        var v = 0L
        for (j in 7 downTo 0) v = (v shl 8) or (b[off + j].toLong() and 0xFF)
        return v
    }

    private fun permute(s: LongArray) {
        val c = LongArray(5)
        val b = LongArray(25)
        for (round in 0 until 24) {
            for (x in 0 until 5) c[x] = s[x] xor s[x + 5] xor s[x + 10] xor s[x + 15] xor s[x + 20]
            for (x in 0 until 5) {
                val d = c[(x + 4) % 5] xor java.lang.Long.rotateLeft(c[(x + 1) % 5], 1)
                for (y in 0 until 5) s[x + 5 * y] = s[x + 5 * y] xor d
            }
            for (x in 0 until 5) for (y in 0 until 5) {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = java.lang.Long.rotateLeft(s[x + 5 * y], R[x + 5 * y])
            }
            for (x in 0 until 5) for (y in 0 until 5) {
                s[x + 5 * y] = b[x + 5 * y] xor (b[(x + 1) % 5 + 5 * y].inv() and b[(x + 2) % 5 + 5 * y])
            }
            s[0] = s[0] xor RC[round]
        }
    }
}

fun keccak256(b: ByteArray): ByteArray = Keccak.hash256(b)
fun keccak256(s: String): ByteArray = Keccak.hash256(s.toByteArray(Charsets.US_ASCII))
