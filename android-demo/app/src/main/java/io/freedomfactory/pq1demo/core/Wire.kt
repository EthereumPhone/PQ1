package io.freedomfactory.pq1demo.core

import java.math.BigInteger

/**
 * Sign-request builders: a Kotlin port of tools/demo_px_flows.py, hid_sign*.py and
 * demo_bybit_replay.py. FlowGoldenTest holds these byte-identical to the Python.
 */
object Wire {
    // ── APDU v2 instructions (nonsecure/src/usb/commands.rs) ──
    const val INS_GET_STATUS = 0x02
    const val INS_LOCK = 0x11
    const val INS_SIGN_USEROP = 0x30
    const val INS_GET_WALLET_ADDRESS = 0x60

    // ── status words ──
    const val SW_OK = 0x9000
    const val SW_DECLINED = 0x6982      // UserRejected (hold-left on the device)
    const val SW_IDLE_WIPED = 0x6984    // 120 s idle timer fired during the ask
    const val SW_NOT_READY = 0x6985     // locked / off-chain gate / fw-update state
    const val SW_REFUSED = 0x6F00       // a firmware gate refused (the screen names it)

    const val C10_SIG_LEN = 4008
    const val SIG_WRAPPER_LEN = 32 + 32 + 32 + 4032  // 4128
    const val HEADER_LEN = 330

    val ENTRY_POINT_V06 = addr("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
    val SHA256_EMPTY = sha256(ByteArray(0))

    // ── chains / tokens / contracts ──
    const val BASE = 8453L
    const val MAINNET = 1L
    val USDC_BASE = addr("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    val WETH_BASE = addr("0x4200000000000000000000000000000000000006")
    val DAI_BASE = addr("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb")
    val WETH_MAINNET = addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
    val USDC_MAINNET = addr("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    val GPV2_SETTLEMENT = addr("0x9008D19f58AAbD9eD0D60971565AA8510560ab41")
    val VAULT_RELAYER = addr("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110")
    val MULTISEND_CALL_ONLY_V150 = addr("0xA83c336B20401aF773B6219BA5027174338D1836")
    val DEMO_SAFE = addr("0x5E7708eb2B75AC5005FDdCfCa67efA8251a0732F")
    // Random, EIP-55 checksummed demo addresses (no known owner).
    const val ALICE = "0xbD547DBAA2fdBc03B3a5F2d900100DB317CE9abB"
    const val BOB = "0xb7A2754cda372E8625CeF80F87eD11d784dA3408"
    val ZERO = zeros(20)

    val TRANSFER = "a9059cbb".hexBytes()
    val APPROVE = "095ea7b3".hexBytes()
    val SET_PRESIGNATURE = "ec6cb13f".hexBytes()
    val MULTI_SEND = "8d80ff0a".hexBytes()
    val APPROVE_HASH = "d4d9bdcd".hexBytes()

    data class Gas(
        val call: Long = 120_000, val ver: Long = 800_000, val pre: Long = 150_000,
        val maxFee: Long = 1_000_000_000, val prio: Long = 100_000_000,
    )

    fun erc20Call(selector: ByteArray, who: ByteArray, amount: BigInteger) =
        cat(selector, wordAddr(who), u256(amount))

    fun userOpHead(
        sender: ByteArray, chainId: Long, flags: Long, nonce: Long,
        to: ByteArray, value: BigInteger, data: ByteArray, gas: Gas = Gas(),
    ): ByteArray = cat(
        u64(chainId), u32(flags), sender, ENTRY_POINT_V06, u256(nonce),
        u256(gas.call), u256(gas.ver), u256(gas.pre), u256(gas.maxFee), u256(gas.prio),
        SHA256_EMPTY, to, u256(value), u16(data.size), data,
    )

    /** Positional trailers (cmd_sign_userop.rs): erc20 | reserved | cow | safe_v1 | selector | self_attest | erc7730. */
    fun trailers(erc20: ByteArray = ByteArray(0), cow: ByteArray = ByteArray(0), safe: ByteArray = ByteArray(0)): ByteArray {
        val empty = ByteArray(0)
        return cat(*listOf(erc20, empty, cow, safe, empty, empty, empty).flatMap { listOf(u16(it.size), it) }.toTypedArray())
    }

    // ── Safe (proto/src/lib.rs safe_v1 canonical, 281 B) ──
    private const val SAFE_LEN = 281
    private const val OFF_CHAIN = 0
    private const val OFF_SAFE = 8
    private const val OFF_TO = 28
    private const val OFF_VALUE = 48
    private const val OFF_DATA_HASH = 80
    private const val OFF_OPERATION = 112
    private const val OFF_SAFE_TX_GAS = 113
    private const val OFF_BASE_GAS = 145
    private const val OFF_GAS_PRICE = 177
    private const val OFF_GAS_TOKEN = 209
    private const val OFF_REFUND = 229
    private const val OFF_NONCE = 249

    private val SAFE_DOMAIN_TH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    private val SAFE_TX_TH = keccak256(
        "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas," +
            "uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    )

    fun safeCanonical(
        chainId: Long, safe: ByteArray, to: ByteArray, value: BigInteger, data: ByteArray,
        nonce: Long, operation: Int, safeTxGas: Long = 0,
    ): ByteArray {
        val c = ByteArray(SAFE_LEN)
        u64(chainId).copyInto(c, OFF_CHAIN)
        safe.copyInto(c, OFF_SAFE)
        to.copyInto(c, OFF_TO)
        u256(value).copyInto(c, OFF_VALUE)
        keccak256(data).copyInto(c, OFF_DATA_HASH)
        c[OFF_OPERATION] = operation.toByte()
        u256(safeTxGas).copyInto(c, OFF_SAFE_TX_GAS)
        u256(nonce).copyInto(c, OFF_NONCE)
        return c
    }

    fun safeTxHash(c: ByteArray): ByteArray {
        fun r(off: Int, len: Int) = c.copyOfRange(off, off + len)
        val domain = keccak256(cat(SAFE_DOMAIN_TH, zeros(24), r(OFF_CHAIN, 8), zeros(12), r(OFF_SAFE, 20)))
        val struct = keccak256(
            cat(
                SAFE_TX_TH, zeros(12), r(OFF_TO, 20), r(OFF_VALUE, 32), r(OFF_DATA_HASH, 32),
                zeros(31), r(OFF_OPERATION, 1), r(OFF_SAFE_TX_GAS, 32), r(OFF_BASE_GAS, 32),
                r(OFF_GAS_PRICE, 32), zeros(12), r(OFF_GAS_TOKEN, 20), zeros(12), r(OFF_REFUND, 20),
                r(OFF_NONCE, 32),
            )
        )
        return keccak256(cat(byteArrayOf(0x19, 0x01), domain, struct))
    }

    /** `approveHash(safeTxHash)` on [safe] + the safe_v1 trailer carrying the full SafeTx. */
    fun safeApproveHash(
        sender: ByteArray, chainId: Long, flags: Long, nonce: Long, safe: ByteArray,
        canonical: ByteArray, innerData: ByteArray,
        erc20: ByteArray = ByteArray(0), cow: ByteArray = ByteArray(0),
    ): ByteArray {
        val h = safeTxHash(canonical)
        return cat(
            userOpHead(sender, chainId, flags, nonce, safe, BigInteger.ZERO, cat(APPROVE_HASH, h)),
            trailers(erc20 = erc20, cow = cow, safe = cat(canonical, u16(innerData.size), innerData)),
        )
    }

    // ── Safe MultiSend ──
    fun multisend(vararg records: ByteArray): ByteArray {
        val packed = cat(*records)
        return cat(MULTI_SEND, u256(0x20), u256(packed.size.toLong()), pad32(packed))
    }

    fun msRecord(to: ByteArray, data: ByteArray, value: BigInteger = BigInteger.ZERO) =
        cat(u8(0), to, u256(value), u256(data.size.toLong()), data)   // op 0 (CALL) only

    // ── CoW (secure/src/tx/eip712/cowswap; order canonical 204 B) ──
    private val COW_ORDER_TH = keccak256(
        "Order(address sellToken,address buyToken,address receiver,uint256 sellAmount," +
            "uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind," +
            "bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
    )

    /** A SELL order; receiver 0 = the owner (the wallet, or the Safe when wrapped). */
    fun cowOrder(
        chainId: Long, sell: ByteArray, buy: ByteArray, sellAmount: BigInteger, buyAmount: BigInteger,
        fee: BigInteger, validTo: Long,
    ): ByteArray {
        val o = ByteArray(204)
        u64(chainId).copyInto(o, 0)
        sell.copyInto(o, 8)
        buy.copyInto(o, 28)
        u256(sellAmount).copyInto(o, 68)
        u256(buyAmount).copyInto(o, 100)
        u256(fee).copyInto(o, 132)
        u32(validTo).copyInto(o, 164)
        o[168] = 0  // SELL
        ByteArray(32) { 0xa7.toByte() }.copyInto(o, 172)  // appData
        return o
    }

    fun cowDigest(c: ByteArray): ByteArray {
        fun r(from: Int, to: Int) = c.copyOfRange(from, to)
        val domain = keccak256(
            cat(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Gnosis Protocol"), keccak256("v2"), zeros(24), r(0, 8), wordAddr(GPV2_SETTLEMENT),
            )
        )
        val kind = keccak256(if (c[168].toInt() == 0) "sell" else "buy")
        val sellBal = keccak256(
            when (c[170].toInt()) { 0 -> "erc20"; 1 -> "external"; else -> "internal" }
        )
        val buyBal = keccak256(if (c[171].toInt() == 0) "erc20" else "internal")
        val struct = keccak256(
            cat(
                COW_ORDER_TH, wordAddr(r(8, 28)), wordAddr(r(28, 48)), wordAddr(r(48, 68)),
                r(68, 100), r(100, 132), zeros(28), r(164, 168), r(172, 204), r(132, 164),
                kind, zeros(31), r(169, 170), sellBal, buyBal,
            )
        )
        return keccak256(cat(byteArrayOf(0x19, 0x01), domain, struct))
    }

    /** `setPreSignature(orderUid, true)`; orderUid = digest | owner | validTo. */
    fun presign(order: ByteArray, owner: ByteArray): ByteArray {
        val uid = cat(cowDigest(order), owner, order.copyOfRange(164, 168))
        val cd = cat(SET_PRESIGNATURE, u256(0x40), u256(1), u256(56), uid, zeros(8))
        check(cd.size == 164)
        return cd
    }

    /** Kind-3 order trailer with both legs' ERC-20 proofs, so the device decodes the legs. */
    fun cowTrailer(order: ByteArray, proofs: ProofSource): ByteArray {
        val chain = order.beLong(0, 8)
        val sell = proofs.erc20(chain, order.copyOfRange(8, 28))
        val buy = proofs.erc20(chain, order.copyOfRange(28, 48))
        return cat(order, u16(sell.size), sell, u16(buy.size), buy)
    }
}

/** ERC-20 Merkle proof bundles, exported from companion-stub/erc20_db.bin by tools/gen_assets.py. */
fun interface ProofSource {
    fun erc20(chainId: Long, token: ByteArray): ByteArray
}
