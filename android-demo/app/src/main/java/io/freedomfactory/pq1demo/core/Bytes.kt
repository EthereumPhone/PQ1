package io.freedomfactory.pq1demo.core

import java.math.BigInteger
import java.security.MessageDigest

private const val HEX = "0123456789abcdef"

fun ByteArray.hex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
    }
    return sb.toString()
}

fun ByteArray.hex0x(): String = "0x" + hex()

fun String.hexBytes(): ByteArray {
    val s = removePrefix("0x").removePrefix("0X")
    require(s.length % 2 == 0) { "odd-length hex" }
    return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}

/** A 20-byte address from "0x…" hex; throws IllegalArgumentException otherwise. */
fun addr(s: String): ByteArray {
    val t = s.trim()
    require(Regex("^(0x|0X)?[0-9a-fA-F]{40}$").matches(t)) { "not a 20-byte hex address" }
    return t.hexBytes()
}

fun u8(n: Int): ByteArray = byteArrayOf(n.toByte())
fun u16(n: Int): ByteArray = byteArrayOf((n ushr 8).toByte(), n.toByte())
fun u32(n: Long): ByteArray = ByteArray(4) { i -> (n ushr (8 * (3 - i))).toByte() }
fun u64(n: Long): ByteArray = ByteArray(8) { i -> (n ushr (8 * (7 - i))).toByte() }

fun u256(n: BigInteger): ByteArray {
    require(n.signum() >= 0 && n.bitLength() <= 256) { "u256 out of range" }
    val raw = n.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
    return ByteArray(32 - raw.size) + raw
}

fun u256(n: Long): ByteArray = u256(BigInteger.valueOf(n))

fun cat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var off = 0
    for (p in parts) {
        p.copyInto(out, off)
        off += p.size
    }
    return out
}

fun zeros(n: Int) = ByteArray(n)

fun wordAddr(a: ByteArray): ByteArray = cat(zeros(12), a)

fun pad32(b: ByteArray): ByteArray = cat(b, zeros((32 - b.size % 32) % 32))

fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

fun ByteArray.beLong(from: Int, len: Int): Long {
    var v = 0L
    for (i in from until from + len) v = (v shl 8) or (this[i].toLong() and 0xFF)
    return v
}

/** Parse a human decimal ("1234.56") into integer base units with [decimals] places. */
fun parseUnits(text: String, decimals: Int): BigInteger {
    val t = text.trim().replace(",", "").replace("_", "")
    require(Regex("^[0-9]+(\\.[0-9]*)?$|^\\.[0-9]+$").matches(t)) { "not a number" }
    val parts = t.split('.')
    val whole = parts[0].ifEmpty { "0" }
    val frac = parts.getOrElse(1) { "" }
    require(frac.length <= decimals) { "at most $decimals decimals" }
    return BigInteger(whole + frac.padEnd(decimals, '0'))
}
