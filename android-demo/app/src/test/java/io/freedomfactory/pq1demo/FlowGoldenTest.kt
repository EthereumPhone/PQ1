package io.freedomfactory.pq1demo

import io.freedomfactory.pq1demo.core.Apdu
import io.freedomfactory.pq1demo.core.Flow
import io.freedomfactory.pq1demo.core.FlowCtx
import io.freedomfactory.pq1demo.core.Flows
import io.freedomfactory.pq1demo.core.ProofSource
import io.freedomfactory.pq1demo.core.Wire
import io.freedomfactory.pq1demo.core.addr
import io.freedomfactory.pq1demo.core.cat
import io.freedomfactory.pq1demo.core.hex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

/**
 * Every flow's request must be byte-identical to what tools/demo_px_flows.py (and
 * demo_bybit_replay.py) send. Goldens come from android-demo/tools/gen_assets.py with
 * sender 0x51…51, nonce 3, validTo 1_800_000_000 and the Python scripts' values, which
 * [pythonValues] passes in: the app's own defaults are larger and use other addresses.
 */
class FlowGoldenTest {
    private val root = File(System.getProperty("user.dir")!!).let { if (File(it, "src").isDirectory) it else File(it, "app") }
    private fun golden(name: String) = File(root, "src/test/resources/golden/$name.bin").readBytes()

    private val proofs = ProofSource { chain, token ->
        File(root, "src/main/assets/erc20/${chain}_${token.hex()}.bin").readBytes()
    }

    private val ctx = FlowCtx(
        sender = ByteArray(20) { 0x51 }, take = 3, validTo = 1_800_000_000,
        safe = addr("0x5afe000000000000000000000000000000000001"), proofs = proofs,
    )

    private val alice = "0x" + "ab".repeat(20)
    private val bob = "0x" + "cd".repeat(20)
    private val wethForUsdc = mapOf("sell" to "0.5", "buy" to "1842.31")
    private val pythonValues = mapOf(
        "send" to mapOf("amount" to "0.0125", "to" to alice),
        "usdc" to mapOf("amount" to "1234.56", "to" to bob),
        "safe_usdc" to mapOf("amount" to "250", "to" to alice),
        "safe_cow" to wethForUsdc,
        "safe_msend" to mapOf("sell" to "1250", "buy" to "1234.987654321098765432"),
        "cow" to wethForUsdc,
    )

    private fun check(flow: Flow, golden: String) {
        val want = golden(golden)
        val got = flow.build(ctx, pythonValues[flow.id] ?: emptyMap()).payload
        assertEquals("${flow.id} length", want.size, got.size)
        assertArrayEquals("${flow.id} bytes", want, got)
        assertNull(flow.validate(emptyMap()))
    }

    @Test fun sendEth() = check(Flows.sendEth, "send")
    @Test fun usdc() = check(Flows.usdc, "erc20")
    @Test fun safeUsdc() = check(Flows.safeUsdc, "safe_usdc")
    @Test fun safeCow() = check(Flows.safeCow, "safe_cow")
    @Test fun safeMultiSend() = check(Flows.safeMultiSend, "safe_msend")
    @Test fun cow() = check(Flows.cow, "cow")
    @Test fun bybit() = check(Flows.bybit, "bybit")

    @Test
    fun hidFraming() {
        val first = cat(byteArrayOf(0xF0.toByte(), 0x30, 0x80.toByte(), 0, 255.toByte()), golden("safe_msend").copyOf(255))
        assertArrayEquals(golden("frames_chained_first"), Apdu.frames(first).reduce { a, b -> cat(a, b) })
        val addr = byteArrayOf(0xF0.toByte(), 0x60, 0, 0, 4, 0, 0, 0, 0)
        assertArrayEquals(golden("frames_get_address"), Apdu.frames(addr).single())
    }

    @Test
    fun editedValuesReachThePayload() {
        val p = Flows.safeUsdc.build(ctx, mapOf("amount" to "900", "to" to "0x" + "12".repeat(20))).payload
        val needle = cat(ByteArray(12), ByteArray(20) { 0x12 }) // recipient word inside the SafeTx data
        assert(p.hex().contains(needle.hex()))
        assertEquals("Amount: at most 6 decimals", Flows.usdc.validate(mapOf("amount" to "1.0000001")))
        assertEquals("Recipient: not a 20-byte hex address", Flows.usdc.validate(mapOf("to" to "0x1234")))
    }
}
