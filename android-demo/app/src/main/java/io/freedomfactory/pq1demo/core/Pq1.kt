package io.freedomfactory.pq1demo.core

/** What came back from one request. */
sealed interface Outcome {
    class Signed(
        val newOffchainCount: Long,
        val initCodeLen: Int,
        val type1Len: Int,
        val ownerIndex: Long,
        val signature: ByteArray,
    ) : Outcome

    data object Declined : Outcome
    class Refused(val sw: Int) : Outcome
    data object IdleWiped : Outcome
    data object NotReady : Outcome
    class Confirmed(val address: ByteArray) : Outcome
    data object Locked : Outcome
    data object Abandoned : Outcome
    class Failed(val message: String) : Outcome
}

class Status(val unlocked: Boolean, val remainingAttempts: Int?)

/** PQ1 commands used by the demo, over [Apdu]. Blocking; call off the main thread. */
class Pq1(io: FrameIo) {
    private val apdu = Apdu(io)

    fun status(timeoutMs: Long = 1_500): Status {
        val r = apdu.send(Wire.INS_GET_STATUS, timeoutMs = timeoutMs)
        if (r.sw != Wire.SW_OK || r.data.isEmpty()) return Status(false, null)
        // commands.rs: byte0 is 0 when UNLOCKED, 1 when locked; byte1 remaining PIN attempts.
        return Status(r.data[0].toInt() == 0, r.data.getOrNull(1)?.toInt()?.and(0xFF))
    }

    /** First call after unlock runs the master keygen (seconds on silicon). */
    fun walletAddress(): ByteArray {
        val r = apdu.send(Wire.INS_GET_WALLET_ADDRESS, u32(0), timeoutMs = 20_000)
        if (r.sw != Wire.SW_OK || r.data.size != 20) throw java.io.IOException("GET_WALLET_ADDRESS failed (SW=%04X)".format(r.sw))
        return r.data
    }

    fun run(req: Request, confirmTimeoutMs: Long, cancelled: () -> Boolean, onWaiting: () -> Unit): Outcome {
        apdu.flush()
        val reply = try {
            when (req.kind) {
                RequestKind.USEROP -> apdu.sendChained(req.ins, req.payload, confirmTimeoutMs, cancelled, onWaiting)
                RequestKind.ADDRESS, RequestKind.LOCK -> {
                    onWaiting()
                    apdu.send(req.ins, req.payload, confirmTimeoutMs, cancelled)
                }
            }
        } catch (e: DeviceTimeout) {
            return Outcome.Failed("No answer from PQ1 (${e.message})")
        } catch (e: java.io.IOException) {
            return if (cancelled()) Outcome.Abandoned else Outcome.Failed(e.message ?: "USB error")
        }
        return interpret(req, reply)
    }

    companion object {
        fun interpret(req: Request, r: Apdu.Reply): Outcome {
            when (r.sw) {
                Wire.SW_OK -> Unit
                Wire.SW_DECLINED -> return Outcome.Declined
                Wire.SW_IDLE_WIPED -> return Outcome.IdleWiped
                Wire.SW_NOT_READY -> return Outcome.NotReady
                else -> return Outcome.Refused(r.sw)
            }
            return when (req.kind) {
                RequestKind.LOCK -> Outcome.Locked
                RequestKind.ADDRESS ->
                    if (r.data.size == 20) Outcome.Confirmed(r.data) else Outcome.Failed("address reply ${r.data.size} B")
                RequestKind.USEROP -> parseUserOp(r.data)
            }
        }

        /** [count 8][init len 4][init][t1 len 4][t1][t2 len 4][t2 = abi.encode(ownerIndex, bytes sig)]. */
        fun parseUserOp(d: ByteArray): Outcome = try {
            var off = 8
            val ic = d.beLong(off, 4).toInt(); off += 4 + ic
            val t1 = d.beLong(off, 4).toInt(); off += 4 + t1
            val t2 = d.beLong(off, 4).toInt(); off += 4
            val w = d.copyOfRange(off, off + t2)
            val sigLen = w.beLong(64, 32).toInt()
            if (off + t2 != d.size || t2 != Wire.SIG_WRAPPER_LEN || sigLen != Wire.C10_SIG_LEN) {
                Outcome.Failed("Signed, but the reply is malformed (${d.size} B)")
            } else {
                Outcome.Signed(d.beLong(0, 8), ic, t1, w.beLong(0, 32), w.copyOfRange(96, 96 + sigLen))
            }
        } catch (e: IndexOutOfBoundsException) {
            Outcome.Failed("Signed, but the reply is truncated (${d.size} B)")
        }
    }
}
