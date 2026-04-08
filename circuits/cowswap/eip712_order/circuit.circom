pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// CowSwap EIP-712 GPv2Order clear-signing circuit (M4, v2)
// ─────────────────────────────────────────────────────────────────────
//
// What this circuit proves
// ────────────────────────
// Given a 164-byte canonical packed GPv2Order encoding and a 64-byte
// human-readable string, the proof attests:
//
//   (1) PoseidonBytes(canonical, 164) == H_tx
//   (2) PoseidonBytes(readable,   64) == H_str
//   (3) The two are linked by a deterministic format function whose
//       output is a 4-line, 16-char-per-line ASCII layout:
//
//       Line 0 (16):  "CowSwap SELL    " or "CowSwap BUY     "
//       Line 1 (16):  "  XXXXXX.YYYY SSSS"  ← sell amount + symbol
//       Line 2 (16):  "for at least:   "
//       Line 3 (16):  "  XXXXXX.YYYY SSSS"  ← buy amount + symbol
//
//       (where lines 1 and 3 are 16 chars exactly:
//          6 int + '.' + 4 frac + ' ' + 4 sym = 16)
//
//       The amount formatter trims leading int zeros to spaces, so
//       "001234.5000 USDC" displays as "  1234.5000 USDC".
//
// What's NEW vs the v1 circuit
// ────────────────────────────
// - Uses the shared `circuits/lib/{poseidon_bytes,erc20_registry,format}.circom`
//   helpers instead of duplicating PoseidonBytes / ByteToHex / etc.
//   The Aave v3 and CowSwap setPreSignature circuits still ship with
//   their own duplicated copies because their committed
//   `circuit_final.zkey` files pin those exact templates; the shared
//   library is the source of truth for any *new* circuit.
//
// - The readable string is now a real human-meaningful trade
//   summary ("1000.0000 USDC for at least 0.5000 WETH") instead of
//   the v1 placeholder "CowSwap SELL exp 0xXXXXXXXX". The token
//   symbols + decimals come from a shared in-circuit
//   `Erc20Registry`; the prover supplies a token_idx for each side
//   and the circuit cross-checks the address bytes against the
//   table. Tokens not in the registry can't be clear-signed
//   (proof construction fails).
//
// - validTo is no longer in the displayed string. It's still bound
//   via the canonical Poseidon hash, and the secure world's EIP-712
//   keccak digest still includes it (so a malicious NS can't
//   substitute a different validTo without breaking the proof or
//   the digest), but the trusted UI shows the trade itself instead.
//   A future v3 can grow the readable layout to include validTo as
//   a 5th line at the cost of bumping Poseidon3 → Poseidon4.
//
// Canonical layout (164 bytes — UNCHANGED from v1)
// ────────────────────────────────────────────────
//
//   [  0..  20)  sellToken          (20 B address)
//   [ 20..  40)  buyToken           (20 B address)
//   [ 40..  60)  receiver           (20 B address)
//   [ 60..  92)  sellAmount         (uint256 BE)
//   [ 92.. 124)  buyAmount          (uint256 BE)
//   [124.. 156)  feeAmount          (uint256 BE)
//   [156.. 160)  validTo            (uint32 BE)
//   [160]        kind               (0 = sell, 1 = buy)
//   [161]        partiallyFillable  (0 = false, 1 = true)
//   [162]        sellTokenBalance   (0 / 1 / 2)
//   [163]        buyTokenBalance    (0 / 1)
//
// uint256 amounts are read into the circuit as a single field element.
// The BLS12-381 prime is ~2^254, so the top two bits of a 32-byte
// uint256 must be zero — `Uint256BytesToField` enforces that. No real
// ERC20 amount comes anywhere near 2^252.

include "../../lib/poseidon_bytes.circom";
include "../../lib/erc20_registry.circom";
include "../../lib/format.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// Uint256BytesToField — pack 32 BE bytes into a single field element
// while constraining the top 2 bits to zero (so the value definitely
// fits in 254 bits and can be safely arithmetized inside the
// FormatTrimmedAmount equations).
template Uint256BytesToField() {
    signal input  bytes[32];
    signal output value;

    // Top byte's top 2 bits must be zero.
    component top_bits = Num2Bits(8);
    top_bits.in <== bytes[0];
    top_bits.out[7] === 0;
    top_bits.out[6] === 0;

    signal acc[33];
    acc[0] <== 0;
    for (var i = 0; i < 32; i++) {
        acc[i+1] <== acc[i] * 256 + bytes[i];
    }
    value <== acc[32];
}

// Eip712OrderProof — root template
template Eip712OrderProof() {
    var CANONICAL_LEN  = 164;
    var STRING_LEN     = 64;
    var MAX_INT_DIGITS = 6;
    var FRAC_DIGITS    = 4;
    var MAX_DECIMALS   = 18;
    var SYMBOL_LEN     = 4;
    var AMOUNT_ASCII   = MAX_INT_DIGITS + 1 + FRAC_DIGITS;  // 11

    // ══ PUBLIC signals ══════════════════════════════════════════════
    // Names kept as `H_tx` / `H_str` for parity with the M3 circuit
    // and the existing 2-IC Groth16 verifier bindings.
    signal input  H_tx;
    signal input  H_str;

    // ══ PRIVATE signals (witness) ═══════════════════════════════════
    signal input  canonical[CANONICAL_LEN];
    signal input  human_string[STRING_LEN];

    // Token registry indices (one per side).
    signal input  sell_token_idx;
    signal input  buy_token_idx;

    // FormatTrimmedAmount witnesses for the sell side.
    signal input  sell_int_digits[MAX_INT_DIGITS];
    signal input  sell_frac_digits[FRAC_DIGITS];
    signal input  sell_n_lz;
    signal input  sell_remainder;

    // FormatTrimmedAmount witnesses for the buy side.
    signal input  buy_int_digits[MAX_INT_DIGITS];
    signal input  buy_frac_digits[FRAC_DIGITS];
    signal input  buy_n_lz;
    signal input  buy_remainder;

    // ─ (1) PoseidonBytes(canonical) === H_tx ────────────────────────
    component h_tx = PoseidonBytes(CANONICAL_LEN);
    for (var i = 0; i < CANONICAL_LEN; i++) h_tx.bytes[i] <== canonical[i];
    h_tx.hash === H_tx;

    // ─ (2) PoseidonBytes(human_string) === H_str ────────────────────
    component h_str = PoseidonBytes(STRING_LEN);
    for (var i = 0; i < STRING_LEN; i++) h_str.bytes[i] <== human_string[i];
    h_str.hash === H_str;

    // ─ (3) kind byte ∈ {0, 1} ───────────────────────────────────────
    signal kind;
    kind <== canonical[160];
    signal kind_check;
    kind_check <== kind * (kind - 1);
    kind_check === 0;

    // ─ (4) Sell-side: address → registry → symbol/decimals/scale ───
    component sell_addr = BytesToAddressField();
    for (var i = 0; i < 20; i++) sell_addr.bytes[i] <== canonical[0 + i];
    component sell_reg = Erc20Registry();
    sell_reg.addr_input <== sell_addr.addr;
    sell_reg.token_idx  <== sell_token_idx;
    sell_reg.ok === 1;

    // ─ (5) Buy-side: same ──────────────────────────────────────────
    component buy_addr = BytesToAddressField();
    for (var i = 0; i < 20; i++) buy_addr.bytes[i] <== canonical[20 + i];
    component buy_reg = Erc20Registry();
    buy_reg.addr_input <== buy_addr.addr;
    buy_reg.token_idx  <== buy_token_idx;
    buy_reg.ok === 1;

    // ─ (6) Sell amount: bytes → field → format ─────────────────────
    component sell_u256 = Uint256BytesToField();
    for (var i = 0; i < 32; i++) sell_u256.bytes[i] <== canonical[60 + i];

    component sell_fmt = FormatTrimmedAmount(MAX_INT_DIGITS, FRAC_DIGITS, MAX_DECIMALS);
    sell_fmt.raw_amount   <== sell_u256.value;
    sell_fmt.scale_factor <== sell_reg.scale_factor;
    for (var i = 0; i < MAX_INT_DIGITS; i++) sell_fmt.int_digits[i]  <== sell_int_digits[i];
    for (var i = 0; i < FRAC_DIGITS;    i++) sell_fmt.frac_digits[i] <== sell_frac_digits[i];
    sell_fmt.n_leading_zeros <== sell_n_lz;
    sell_fmt.remainder       <== sell_remainder;
    sell_fmt.ok === 1;

    // ─ (7) Buy amount: same ────────────────────────────────────────
    component buy_u256 = Uint256BytesToField();
    for (var i = 0; i < 32; i++) buy_u256.bytes[i] <== canonical[92 + i];

    component buy_fmt = FormatTrimmedAmount(MAX_INT_DIGITS, FRAC_DIGITS, MAX_DECIMALS);
    buy_fmt.raw_amount   <== buy_u256.value;
    buy_fmt.scale_factor <== buy_reg.scale_factor;
    for (var i = 0; i < MAX_INT_DIGITS; i++) buy_fmt.int_digits[i]  <== buy_int_digits[i];
    for (var i = 0; i < FRAC_DIGITS;    i++) buy_fmt.frac_digits[i] <== buy_frac_digits[i];
    buy_fmt.n_leading_zeros <== buy_n_lz;
    buy_fmt.remainder       <== buy_remainder;
    buy_fmt.ok === 1;

    // ─ (8) Line 0: "CowSwap SELL    " or "CowSwap BUY     " ────────
    //
    // Mux per byte:
    //   line0[i] = SELL_LINE[i] + kind * (BUY_LINE[i] - SELL_LINE[i])
    //
    // SELL_LINE = "CowSwap SELL    "
    //   C=67 o=111 w=119 S=83 w=119 a=97 p=112 ' '=32 S=83 E=69 L=76 L=76 ' ' ' ' ' ' ' '
    // BUY_LINE  = "CowSwap BUY     "
    //   C=67 o=111 w=119 S=83 w=119 a=97 p=112 ' '=32 B=66 U=85 Y=89 ' ' ' ' ' ' ' ' ' '
    var SELL_LINE[16] = [67,111,119,83,119,97,112,32, 83,69,76,76,32,32,32,32];
    var BUY_LINE [16] = [67,111,119,83,119,97,112,32, 66,85,89,32,32,32,32,32];

    signal line0_expected[16];
    for (var i = 0; i < 16; i++) {
        line0_expected[i] <== SELL_LINE[i] + kind * (BUY_LINE[i] - SELL_LINE[i]);
        human_string[i]   === line0_expected[i];
    }

    // ─ (9) Line 1: "  XXXXXX.YYYY SSSS"  (16 chars) ─────────────────
    //
    //   [16..27)  sell_fmt.ascii (11 chars)
    //   [27]      ' '
    //   [28..32)  sell_reg.symbol (4 chars)
    for (var i = 0; i < AMOUNT_ASCII; i++) {
        human_string[16 + i] === sell_fmt.ascii[i];
    }
    human_string[16 + AMOUNT_ASCII] === 32;  // ' '
    for (var i = 0; i < SYMBOL_LEN; i++) {
        human_string[16 + AMOUNT_ASCII + 1 + i] === sell_reg.symbol[i];
    }

    // ─ (10) Line 2: "for at least:   " ──────────────────────────────
    //   f=102 o=111 r=114 ' '=32 a=97 t=116 ' '=32 l=108 e=101 a=97 s=115 t=116 :=58 ' ' ' ' ' '
    var LINE2[16] = [102,111,114,32,97,116,32,108,101,97,115,116,58,32,32,32];
    for (var i = 0; i < 16; i++) {
        human_string[32 + i] === LINE2[i];
    }

    // ─ (11) Line 3: "  XXXXXX.YYYY SSSS" (buy side) ─────────────────
    for (var i = 0; i < AMOUNT_ASCII; i++) {
        human_string[48 + i] === buy_fmt.ascii[i];
    }
    human_string[48 + AMOUNT_ASCII] === 32;
    for (var i = 0; i < SYMBOL_LEN; i++) {
        human_string[48 + AMOUNT_ASCII + 1 + i] === buy_reg.symbol[i];
    }

    // No explicit padding constraint: every byte of `human_string` is
    // already pinned by one of the constraints above (lines 0..3 each
    // constrain all 16 bytes), so the prover has zero degrees of
    // freedom in the readable string.
}

component main {public [H_tx, H_str]} = Eip712OrderProof();
