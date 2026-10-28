package io.freedomfactory.pq1demo

import io.freedomfactory.pq1demo.core.hex
import io.freedomfactory.pq1demo.core.keccak256
import org.junit.Assert.assertEquals
import org.junit.Test

class KeccakTest {
    @Test
    fun knownVectors() {
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", keccak256(ByteArray(0)).hex())
        assertEquals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", keccak256("abc").hex())
    }

    @Test
    fun rateBoundaries() {
        // pycryptodome keccak(digest_bits=256) over bytes(i % 251 for i in range(n))
        val want = mapOf(
            135 to "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62",
            136 to "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e",
            137 to "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db",
            300 to "4699841dafd5e26cca72b05a41d38c96b4b468e5a6cbf694cbebe77dacdf6528",
        )
        for ((n, h) in want) assertEquals("n=$n", h, keccak256(ByteArray(n) { (it % 251).toByte() }).hex())
    }
}
