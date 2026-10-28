package io.freedomfactory.pq1demo.core

import io.freedomfactory.pq1demo.core.Wire.ALICE
import io.freedomfactory.pq1demo.core.Wire.BASE
import io.freedomfactory.pq1demo.core.Wire.BOB
import io.freedomfactory.pq1demo.core.Wire.DAI_BASE
import io.freedomfactory.pq1demo.core.Wire.GPV2_SETTLEMENT
import io.freedomfactory.pq1demo.core.Wire.MAINNET
import io.freedomfactory.pq1demo.core.Wire.USDC_BASE
import io.freedomfactory.pq1demo.core.Wire.USDC_MAINNET
import io.freedomfactory.pq1demo.core.Wire.WETH_BASE
import io.freedomfactory.pq1demo.core.Wire.WETH_MAINNET
import java.math.BigInteger

/** What a correct device does with the request. */
enum class Expect { SIGN, REFUSE, CONFIRM, LOCK }

enum class RequestKind { USEROP, ADDRESS, LOCK }

class Request(val ins: Int, val payload: ByteArray, val kind: RequestKind)

enum class FieldKind { AMOUNT, ADDRESS }

data class Field(
    val key: String,
    val label: String,
    val default: String,
    val kind: FieldKind,
    val decimals: Int = 0,
    val suffix: String = "",
)

/**
 * Per-request inputs. [take] counts requests sent this session: it is the UserOp nonce and
 * offsets the Safe nonce (17 + take), exactly as demo_px_flows.py does.
 */
class FlowCtx(
    val sender: ByteArray,
    val take: Long,
    val validTo: Long,
    val safe: ByteArray,
    val proofs: ProofSource,
    val flags: Long = 0,
)

class Values(private val m: Map<String, String>, private val fields: List<Field>) {
    private fun field(k: String) = fields.first { it.key == k }
    private fun raw(k: String) = m[k] ?: field(k).default
    fun amount(k: String): BigInteger = parseUnits(raw(k), field(k).decimals)
    fun address(k: String): ByteArray = addr(raw(k))
    fun display(k: String): String = raw(k).trim()
}

class Flow(
    val id: String,
    val group: String,
    val title: String,
    val blurb: String,
    val chain: String,
    val expect: Expect,
    val onDevice: List<String>,
    val fields: List<Field> = emptyList(),
    private val builder: (FlowCtx, Values) -> Request,
) {
    fun build(ctx: FlowCtx, values: Map<String, String> = emptyMap()): Request = builder(ctx, Values(values, fields))

    /** Null when every field parses, else the first problem as "Label: reason". */
    fun validate(values: Map<String, String>): String? {
        val v = Values(values, fields)
        for (f in fields) {
            try {
                when (f.kind) {
                    FieldKind.AMOUNT -> v.amount(f.key)
                    FieldKind.ADDRESS -> v.address(f.key)
                }
            } catch (e: Exception) {
                return "${f.label}: ${e.message}"
            }
        }
        return null
    }
}

object Flows {
    const val SAFE_NONCE_BASE = 17L
    const val GROUP_SAFE = "Safe{Wallet}"
    const val GROUP_WALLET = "Smart wallet"
    const val GROUP_ATTACK = "Attack replay"

    private val usdcAmount = { d: String -> Field("amount", "Amount", d, FieldKind.AMOUNT, 6, "USDC") }
    private val recipient = { d: String -> Field("to", "Recipient", d, FieldKind.ADDRESS) }

    val safeUsdc = Flow(
        id = "safe_usdc", group = GROUP_SAFE,
        title = "Safe · USDC payment",
        blurb = "A Safe pays USDC. PQ1 re-hashes the SafeTx itself and decodes the transfer.",
        chain = "Base", expect = Expect.SIGN,
        onDevice = listOf(
            "APPROVE SAFE TX? opening ask",
            "Network, Safe account, Safe nonce",
            "USD Coin (verified), full recipient address, exact amount",
            "Read to the last screen, then press both buttons",
        ),
        fields = listOf(usdcAmount("1,850,000"), recipient(ALICE)),
    ) { c, v ->
        val raw = Wire.erc20Call(Wire.TRANSFER, v.address("to"), v.amount("amount"))
        val canonical = Wire.safeCanonical(BASE, c.safe, USDC_BASE, BigInteger.ZERO, raw, SAFE_NONCE_BASE + c.take, 0)
        Request(
            Wire.INS_SIGN_USEROP,
            Wire.safeApproveHash(c.sender, BASE, c.flags, c.take, c.safe, canonical, raw, erc20 = c.proofs.erc20(BASE, USDC_BASE)),
            RequestKind.USEROP,
        )
    }

    val safeCow = Flow(
        id = "safe_cow", group = GROUP_SAFE,
        title = "Safe · CoW swap",
        blurb = "A Safe pre-signs a CoW Protocol order. PQ1 decodes the full order, owned by the Safe.",
        chain = "Base", expect = Expect.SIGN,
        onDevice = listOf(
            "Safe banner, then the order headline",
            "SELL WETH for at least USDC, both tokens verified",
            "Receiver = the Safe, fee, expiry",
        ),
        fields = listOf(
            Field("sell", "Sell", "500", FieldKind.AMOUNT, 18, "WETH"),
            Field("buy", "Buy at least", "1,842,310", FieldKind.AMOUNT, 6, "USDC"),
        ),
    ) { c, v ->
        val order = Wire.cowOrder(BASE, WETH_BASE, USDC_BASE, v.amount("sell"), v.amount("buy"), BigInteger.TEN.pow(15), c.validTo)
        val data = Wire.presign(order, c.safe)
        val canonical = Wire.safeCanonical(BASE, c.safe, GPV2_SETTLEMENT, BigInteger.ZERO, data, SAFE_NONCE_BASE + c.take, 0)
        Request(
            Wire.INS_SIGN_USEROP,
            Wire.safeApproveHash(c.sender, BASE, c.flags, c.take, c.safe, canonical, data, cow = Wire.cowTrailer(order, c.proofs)),
            RequestKind.USEROP,
        )
    }

    val safeMultiSend = Flow(
        id = "safe_msend", group = GROUP_SAFE,
        title = "Safe · CoW swap, Safe UI batch",
        blurb = "What the Safe web app really sends: approve + presign in a MultiSend DELEGATECALL. Each record is decoded.",
        chain = "Base", expect = Expect.SIGN,
        onDevice = listOf(
            "MultiSendCallOnly v1.5.0, 2 records",
            "RECORD 1/2: approve USDC to the CoW VaultRelayer",
            "RECORD 2/2: SELL USDC for at least DAI (exact, wrapped)",
        ),
        fields = listOf(
            Field("sell", "Sell", "2,500,000", FieldKind.AMOUNT, 6, "USDC"),
            Field("buy", "Buy at least", "2,497,512.345678901234567890", FieldKind.AMOUNT, 18, "DAI"),
        ),
    ) { c, v ->
        val sell = v.amount("sell")
        val order = Wire.cowOrder(BASE, USDC_BASE, DAI_BASE, sell, v.amount("buy"), BigInteger.ZERO, c.validTo)
        val data = Wire.multisend(
            Wire.msRecord(USDC_BASE, Wire.erc20Call(Wire.APPROVE, Wire.VAULT_RELAYER, sell)),
            Wire.msRecord(GPV2_SETTLEMENT, Wire.presign(order, c.safe)),
        )
        val canonical = Wire.safeCanonical(BASE, c.safe, Wire.MULTISEND_CALL_ONLY_V150, BigInteger.ZERO, data, SAFE_NONCE_BASE + c.take, 1)
        Request(
            Wire.INS_SIGN_USEROP,
            Wire.safeApproveHash(
                c.sender, BASE, c.flags, c.take, c.safe, canonical, data,
                erc20 = c.proofs.erc20(BASE, USDC_BASE), cow = Wire.cowTrailer(order, c.proofs),
            ),
            RequestKind.USEROP,
        )
    }

    val usdc = Flow(
        id = "usdc", group = GROUP_WALLET,
        title = "Send USDC",
        blurb = "ERC-20 transfer from the PQ1 smart wallet, with the token proven against the on-device DB.",
        chain = "Base", expect = Expect.SIGN,
        onDevice = listOf("TRANSFER, USD Coin (verified)", "Full recipient address and exact amount", "Network Base, max fee"),
        fields = listOf(usdcAmount("487,250"), recipient(BOB)),
    ) { c, v ->
        val data = Wire.erc20Call(Wire.TRANSFER, v.address("to"), v.amount("amount"))
        Request(
            Wire.INS_SIGN_USEROP,
            cat(
                Wire.userOpHead(c.sender, BASE, c.flags, c.take, USDC_BASE, BigInteger.ZERO, data),
                Wire.trailers(erc20 = c.proofs.erc20(BASE, USDC_BASE)),
            ),
            RequestKind.USEROP,
        )
    }

    val sendEth = Flow(
        id = "send", group = GROUP_WALLET,
        title = "Send ETH",
        blurb = "Plain value transfer.",
        chain = "Base", expect = Expect.SIGN,
        onDevice = listOf("SEND, amount in ETH", "Full recipient address", "Network Base, max fee"),
        fields = listOf(Field("amount", "Amount", "150", FieldKind.AMOUNT, 18, "ETH"), recipient(ALICE)),
    ) { c, v ->
        Request(
            Wire.INS_SIGN_USEROP,
            cat(Wire.userOpHead(c.sender, BASE, c.flags, c.take, v.address("to"), v.amount("amount"), ByteArray(0)), Wire.trailers()),
            RequestKind.USEROP,
        )
    }

    val cow = Flow(
        id = "cow", group = GROUP_WALLET,
        title = "CoW swap",
        blurb = "The smart wallet pre-signs a CoW order directly. Order decoded on-device, no hash to trust.",
        chain = "Ethereum", expect = Expect.SIGN,
        onDevice = listOf("CoW order headline", "SELL WETH for at least USDC, fee, expiry", "Receiver = your wallet"),
        fields = listOf(
            Field("sell", "Sell", "250", FieldKind.AMOUNT, 18, "WETH"),
            Field("buy", "Buy at least", "921,155", FieldKind.AMOUNT, 6, "USDC"),
        ),
    ) { c, v ->
        val order = Wire.cowOrder(MAINNET, WETH_MAINNET, USDC_MAINNET, v.amount("sell"), v.amount("buy"), BigInteger.TEN.pow(15), c.validTo)
        Request(
            Wire.INS_SIGN_USEROP,
            cat(
                Wire.userOpHead(c.sender, MAINNET, c.flags, c.take, GPV2_SETTLEMENT, BigInteger.ZERO, Wire.presign(order, c.sender)),
                Wire.trailers(cow = Wire.cowTrailer(order, c.proofs)),
            ),
            RequestKind.USEROP,
        )
    }

    // demo_bybit_replay.py: the SafeTx Bybit's signers approved on 2025-02-21.
    val BYBIT_SAFE = addr("0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4")
    val BYBIT_ATTACKER = addr("0x96221423681A6d52E184D440a8eFCEbB105C7242")
    val BYBIT_SWEEPER = addr("0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516")

    fun bybitCanonical(): Pair<ByteArray, ByteArray> {
        val raw = Wire.erc20Call(Wire.TRANSFER, BYBIT_SWEEPER, BigInteger.ZERO)
        return Wire.safeCanonical(MAINNET, BYBIT_SAFE, BYBIT_ATTACKER, BigInteger.ZERO, raw, 71, 1, safeTxGas = 45746) to raw
    }

    val bybit = Flow(
        id = "bybit", group = GROUP_ATTACK,
        title = "Bybit hack, replayed",
        blurb = "Feb 2025, ~\$1.5B. Signers saw a routine transfer; their devices got a DELEGATECALL to attacker code. PQ1 decodes it and refuses.",
        chain = "Ethereum", expect = Expect.REFUSE,
        onDevice = listOf(
            "No confirm screen at all",
            "Refusal names the DELEGATECALL to a non-allowlisted contract",
            "No signature leaves the device",
        ),
    ) { c, _ ->
        val (canonical, raw) = bybitCanonical()
        Request(
            Wire.INS_SIGN_USEROP,
            Wire.safeApproveHash(c.sender, MAINNET, c.flags, c.take, BYBIT_SAFE, canonical, raw),
            RequestKind.USEROP,
        )
    }

    val showAddress = Flow(
        id = "address", group = "Device", title = "Show address on PQ1",
        blurb = "Confirm the wallet address on the trusted screen.",
        chain = "", expect = Expect.CONFIRM, onDevice = listOf("Your wallet address, then confirm"),
    ) { _, _ -> Request(Wire.INS_GET_WALLET_ADDRESS, cat(u32(0), u8(1)), RequestKind.ADDRESS) }

    val lock = Flow(
        id = "lock", group = "Device", title = "Lock PQ1",
        blurb = "Wipe the unlocked session; PIN entry needed again.",
        chain = "", expect = Expect.LOCK, onDevice = listOf("LOCKED padlock, then the PIN row"),
    ) { _, _ -> Request(Wire.INS_LOCK, ByteArray(0), RequestKind.LOCK) }

    val all = listOf(safeUsdc, safeCow, safeMultiSend, usdc, sendEth, cow, bybit)
    val device = listOf(showAddress, lock)
}
