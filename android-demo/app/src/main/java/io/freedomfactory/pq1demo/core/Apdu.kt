package io.freedomfactory.pq1demo.core

import java.io.IOException

/** One 64-byte HID report in each direction. Implemented over Android USB host in usb/UsbHid.kt. */
interface FrameIo {
    fun write(frame: ByteArray)

    /** Next IN report, or null if none arrived within [timeoutMs]. Throws IOException if the link is gone. */
    fun read(timeoutMs: Int): ByteArray?
}

class DeviceTimeout(msg: String) : IOException(msg)

/**
 * APDU v2 over the PQ1 HID transport (docs/companion/usb-protocol-v2.md; port of
 * tools/hid_smoke.py + hid_sign.py): 64-byte frames on channel 0x0001, tag 0x05,
 * request chaining with P1=0x80, chunked replies drained with GET_RESPONSE.
 */
class Apdu(private val io: FrameIo) {
    companion object {
        const val CLA = 0xF0
        const val REPORT = 64
        const val TAG_APDU = 0x05
        const val CHANNEL = 0x0001
        const val FIRST_DATA = REPORT - 7
        const val CONT_DATA = REPORT - 5
        const val P1_MORE = 0x80
        const val P1_LAST = 0x00
        const val INS_GET_RESPONSE = 0xC0
        const val SW1_MORE = 0x61

        fun frames(apdu: ByteArray): List<ByteArray> {
            val out = mutableListOf<ByteArray>()
            val first = ByteArray(REPORT)
            first[0] = (CHANNEL ushr 8).toByte(); first[1] = CHANNEL.toByte(); first[2] = TAG_APDU.toByte()
            first[5] = (apdu.size ushr 8).toByte(); first[6] = apdu.size.toByte()
            var n = minOf(FIRST_DATA, apdu.size)
            apdu.copyInto(first, 7, 0, n)
            out += first
            var off = n
            var seq = 1
            while (off < apdu.size) {
                val f = ByteArray(REPORT)
                f[0] = (CHANNEL ushr 8).toByte(); f[1] = CHANNEL.toByte(); f[2] = TAG_APDU.toByte()
                f[3] = (seq ushr 8).toByte(); f[4] = seq.toByte()
                n = minOf(CONT_DATA, apdu.size - off)
                apdu.copyInto(f, 5, off, off + n)
                out += f
                off += n
                seq++
            }
            return out
        }
    }

    data class Reply(val sw: Int, val data: ByteArray)

    /** Discard stale IN reports (e.g. a reply to a request a previous session abandoned). */
    fun flush() {
        while (io.read(20) != null) { /* drop */ }
    }

    private fun readReply(timeoutMs: Long, cancelled: () -> Boolean): Reply {
        val deadline = System.currentTimeMillis() + timeoutMs
        val buf = java.io.ByteArrayOutputStream()
        var expected = 0
        var seq = 0
        while (true) {
            if (cancelled()) throw IOException("cancelled")
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) throw DeviceTimeout("no reply within ${timeoutMs / 1000}s")
            val f = io.read(minOf(left, 250L).toInt()) ?: continue
            if (f.size < 7 || f[2].toInt() != TAG_APDU) continue
            val rSeq = ((f[3].toInt() and 0xFF) shl 8) or (f[4].toInt() and 0xFF)
            if (rSeq != seq) throw IOException("HID seq mismatch: want $seq, got $rSeq")
            val off: Int
            val chunk: Int
            if (seq == 0) {
                expected = ((f[5].toInt() and 0xFF) shl 8) or (f[6].toInt() and 0xFF)
                off = 7; chunk = minOf(FIRST_DATA, expected)
            } else {
                off = 5; chunk = minOf(CONT_DATA, expected - buf.size())
            }
            buf.write(f, off, minOf(chunk, f.size - off))
            seq++
            if (buf.size() >= expected) break
        }
        val r = buf.toByteArray().copyOf(expected)
        if (r.size < 2) throw IOException("reply too short (${r.size} B)")
        val sw = ((r[r.size - 2].toInt() and 0xFF) shl 8) or (r[r.size - 1].toInt() and 0xFF)
        return Reply(sw, r.copyOf(r.size - 2))
    }

    private fun exchange(apdu: ByteArray, timeoutMs: Long, cancelled: () -> Boolean): Reply {
        for (f in frames(apdu)) io.write(f)
        return readReply(timeoutMs, cancelled)
    }

    private fun drain(first: Reply, cancelled: () -> Boolean): Reply {
        var r = first
        val acc = java.io.ByteArrayOutputStream().apply { write(first.data) }
        var rounds = 0
        while ((r.sw ushr 8) == SW1_MORE) {
            if (++rounds > 200) throw IOException("GET_RESPONSE drain exceeded 200 rounds")
            r = exchange(byteArrayOf(CLA.toByte(), INS_GET_RESPONSE.toByte(), 0, 0, 0), 5_000, cancelled)
            acc.write(r.data)
        }
        return Reply(r.sw, acc.toByteArray())
    }

    /** Single APDU (payload ≤ 255 B), reply drained. */
    fun send(ins: Int, data: ByteArray = ByteArray(0), timeoutMs: Long = 5_000, cancelled: () -> Boolean = { false }): Reply {
        require(data.size <= 255)
        val apdu = cat(byteArrayOf(CLA.toByte(), ins.toByte(), P1_LAST.toByte(), 0, data.size.toByte()), data)
        return drain(exchange(apdu, timeoutMs, cancelled), cancelled)
    }

    /**
     * Chained send; the last block's reply may take up to [lastTimeoutMs] (the user reading the
     * device screens). [onLastSent] fires once every block is on the wire.
     */
    fun sendChained(
        ins: Int, payload: ByteArray, lastTimeoutMs: Long,
        cancelled: () -> Boolean = { false }, onLastSent: () -> Unit = {},
    ): Reply {
        var off = 0
        while (off < payload.size) {
            val n = minOf(255, payload.size - off)
            val last = off + n >= payload.size
            val apdu = cat(
                byteArrayOf(CLA.toByte(), ins.toByte(), (if (last) P1_LAST else P1_MORE).toByte(), 0, n.toByte()),
                payload.copyOfRange(off, off + n),
            )
            if (last) {
                for (f in frames(apdu)) io.write(f)
                onLastSent()
                return drain(readReply(lastTimeoutMs, cancelled), cancelled)
            }
            val r = drain(exchange(apdu, 5_000, cancelled), cancelled)
            if (r.sw != Wire.SW_OK) return r
            off += n
        }
        throw IllegalArgumentException("empty payload")
    }
}
