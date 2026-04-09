pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// CowSwap EIP-712 GPv2Order clear-signing circuit (M4, v3)
// ─────────────────────────────────────────────────────────────────────
//
// v3 scope: "works for every CowSwap order" — any token in
// `secure/data/erc20.json`, any chain in that DB, any amount up to
// ~10^10 units, with real appData bound into the digest, and sub-
// 0.0001 precision rejected instead of silently truncated.
//
// Three public signals:
//
//   H_tx   = PoseidonBytes(canonical, 204)
//   H_str  = PoseidonBytes(readable,  128)
//   H_root = BLS12-381 Poseidon-Merkle root of the parallel ERC20
//            registry `dbgen` builds next to the SHA-256 tree. The
//            firmware's `ERC20_POSEIDON_ROOT` constant is fed straight
//            into the verifier as `pub2`.
//
// Canonical layout (204 bytes — grew from v2's 164):
//
//   [  0..  8)  chain_id          (u64 BE)
//   [  8.. 28)  sellToken         (20 B address)
//   [ 28.. 48)  buyToken          (20 B address)
//   [ 48.. 68)  receiver          (20 B address)
//   [ 68..100)  sellAmount        (uint256 BE)
//   [100..132)  buyAmount         (uint256 BE)
//   [132..164)  feeAmount         (uint256 BE)
//   [164..168)  validTo           (u32 BE)
//   [168]       kind              (0=sell, 1=buy)
//   [169]       partiallyFillable (0/1)
//   [170]       sellTokenBalance  (0/1/2)
//   [171]       buyTokenBalance   (0/1)
//   [172..204)  appData           (bytes32)
//
// Readable layout (128 bytes = 8 lines × 16 cols):
//
//   Line 0 (16): "CowSwap SELL    " or "CowSwap BUY     "
//   Line 1 (16): "SELL:           "
//   Line 2 (16): " XXXXXXXXXX.YYYY"   ← 1 pad + 10 int + '.' + 4 frac
//   Line 3 (16): "          SSSSSS"   ← 10 pad + 6-char symbol
//   Line 4 (16): "for at least:   "
//   Line 5 (16): " XXXXXXXXXX.YYYY"
//   Line 6 (16): "          SSSSSS"
//   Line 7 (16): "                "   ← reserved
//
// Moving the symbol onto its own line frees the amount row up to the
// full 16 cols, enabling MAX_INT_DIGITS = 10 (amounts up to 10^10-1
// token units — ~$100B for 6-decimal stables). SYMBOL_LEN = 6 covers
// the widest ticker in `erc20.json` (WMATIC, PENDLE).
//
// What the firmware displays IN ADDITION to the circuit-bound readable:
//
//   - receiver (hex tail)         — decoded by SE from canonical
//   - validTo  (decimal epoch)    — decoded by SE from canonical
//   - feeAmount / partial / balance enums / appData prefix+suffix
//
// These fields are Poseidon-bound via `H_tx`, so the SE-rendered
// pages are still tamper-proof — they just don't need the circuit to
// format them into ASCII (formatting u32 dates and 20-byte hex
// strings in-circuit is expensive; the firmware does it cheaply).

include "../../lib/poseidon_bytes.circom";
include "../../lib/merkle_erc20_registry.circom";
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

// U64BytesToField — pack 8 BE bytes into a single scalar for the
// canonical chain_id field.
template U64BytesToField() {
    signal input  bytes[8];
    signal output value;

    signal acc[9];
    acc[0] <== 0;
    for (var i = 0; i < 8; i++) {
        acc[i+1] <== acc[i] * 256 + bytes[i];
    }
    value <== acc[8];
}

// Eip712OrderProof — root template
template Eip712OrderProof() {
    var CANONICAL_LEN  = 204;
    var STRING_LEN     = 128;
    var MAX_INT_DIGITS = 10;
    var FRAC_DIGITS    = 4;
    var MAX_DECIMALS   = 18;
    var SYMBOL_LEN     = 6;
    var TREE_HEIGHT    = 8;
    var AMOUNT_ASCII   = MAX_INT_DIGITS + 1 + FRAC_DIGITS;  // 15

    // ══ PUBLIC signals ══════════════════════════════════════════════
    signal input  H_tx;
    signal input  H_str;
    signal input  H_root;

    // ══ PRIVATE signals (witness) ═══════════════════════════════════
    signal input  canonical[CANONICAL_LEN];
    signal input  human_string[STRING_LEN];

    // Sell-side Merkle proof witness.
    signal input  sell_decimals;
    signal input  sell_symbol_bytes[SYMBOL_LEN];
    signal input  sell_symbol_len;
    signal input  sell_path_sel[TREE_HEIGHT];
    signal input  sell_siblings[TREE_HEIGHT];

    // Buy-side Merkle proof witness.
    signal input  buy_decimals;
    signal input  buy_symbol_bytes[SYMBOL_LEN];
    signal input  buy_symbol_len;
    signal input  buy_path_sel[TREE_HEIGHT];
    signal input  buy_siblings[TREE_HEIGHT];

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
    component h_str_hash = PoseidonBytes(STRING_LEN);
    for (var i = 0; i < STRING_LEN; i++) h_str_hash.bytes[i] <== human_string[i];
    h_str_hash.hash === H_str;

    // ─ (3) Decode canonical fields ──────────────────────────────────
    component chain_id_pack = U64BytesToField();
    for (var i = 0; i < 8; i++) chain_id_pack.bytes[i] <== canonical[i];
    signal chain_id;
    chain_id <== chain_id_pack.value;

    // kind byte ∈ {0, 1}.
    signal kind;
    kind <== canonical[168];
    signal kind_check;
    kind_check <== kind * (kind - 1);
    kind_check === 0;

    // partiallyFillable ∈ {0, 1}.
    signal part_fill;
    part_fill <== canonical[169];
    signal part_check;
    part_check <== part_fill * (part_fill - 1);
    part_check === 0;

    // sellTokenBalance ∈ {0, 1, 2}: enforce via (s)(s-1)(s-2) === 0.
    signal sell_bal;
    sell_bal <== canonical[170];
    signal sell_bal_c1;
    sell_bal_c1 <== sell_bal * (sell_bal - 1);
    signal sell_bal_check;
    sell_bal_check <== sell_bal_c1 * (sell_bal - 2);
    sell_bal_check === 0;

    // buyTokenBalance ∈ {0, 1}.
    signal buy_bal;
    buy_bal <== canonical[171];
    signal buy_bal_check;
    buy_bal_check <== buy_bal * (buy_bal - 1);
    buy_bal_check === 0;

    // ─ (4) Sell-side Merkle registry lookup ────────────────────────
    component sell_reg = MerkleErc20Registry(TREE_HEIGHT, SYMBOL_LEN, MAX_DECIMALS);
    for (var i = 0; i < 20; i++) sell_reg.address_bytes[i] <== canonical[8 + i];
    sell_reg.chain_id <== chain_id;
    sell_reg.decimals <== sell_decimals;
    for (var i = 0; i < SYMBOL_LEN; i++) sell_reg.symbol_bytes[i] <== sell_symbol_bytes[i];
    sell_reg.symbol_len <== sell_symbol_len;
    for (var i = 0; i < TREE_HEIGHT; i++) sell_reg.path_sel[i] <== sell_path_sel[i];
    for (var i = 0; i < TREE_HEIGHT; i++) sell_reg.siblings[i] <== sell_siblings[i];
    sell_reg.root <== H_root;
    sell_reg.ok === 1;

    // ─ (5) Buy-side Merkle registry lookup ─────────────────────────
    component buy_reg = MerkleErc20Registry(TREE_HEIGHT, SYMBOL_LEN, MAX_DECIMALS);
    for (var i = 0; i < 20; i++) buy_reg.address_bytes[i] <== canonical[28 + i];
    buy_reg.chain_id <== chain_id;
    buy_reg.decimals <== buy_decimals;
    for (var i = 0; i < SYMBOL_LEN; i++) buy_reg.symbol_bytes[i] <== buy_symbol_bytes[i];
    buy_reg.symbol_len <== buy_symbol_len;
    for (var i = 0; i < TREE_HEIGHT; i++) buy_reg.path_sel[i] <== buy_path_sel[i];
    for (var i = 0; i < TREE_HEIGHT; i++) buy_reg.siblings[i] <== buy_siblings[i];
    buy_reg.root <== H_root;
    buy_reg.ok === 1;

    // ─ (6) Sell amount: bytes → field → format ─────────────────────
    component sell_u256 = Uint256BytesToField();
    for (var i = 0; i < 32; i++) sell_u256.bytes[i] <== canonical[68 + i];

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
    for (var i = 0; i < 32; i++) buy_u256.bytes[i] <== canonical[100 + i];

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
    //   SELL_LINE = [67,111,119,83,119,97,112,32, 83,69,76,76,32,32,32,32]
    //   BUY_LINE  = [67,111,119,83,119,97,112,32, 66,85,89,32,32,32,32,32]
    //
    // Mux per byte: line0[i] = SELL_LINE[i] + kind * (BUY_LINE[i] - SELL_LINE[i])
    var SELL_LINE[16] = [67,111,119,83,119,97,112,32, 83,69,76,76,32,32,32,32];
    var BUY_LINE [16] = [67,111,119,83,119,97,112,32, 66,85,89,32,32,32,32,32];
    signal line0_expected[16];
    for (var i = 0; i < 16; i++) {
        line0_expected[i] <== SELL_LINE[i] + kind * (BUY_LINE[i] - SELL_LINE[i]);
        human_string[i]   === line0_expected[i];
    }

    // ─ (9) Line 1: "SELL:           " (16 hardcoded bytes) ─────────
    //   S=83 E=69 L=76 L=76 :=58 ' '=32
    var LINE1[16] = [83,69,76,76,58,32,32,32,32,32,32,32,32,32,32,32];
    for (var i = 0; i < 16; i++) {
        human_string[16 + i] === LINE1[i];
    }

    // ─ (10) Line 2: " XXXXXXXXXX.YYYY" (sell amount, right-wide) ───
    //
    //   [32]      ' '                   (1 leading pad)
    //   [33..48)  sell_fmt.ascii[0..15) (15 chars: 10 int + '.' + 4 frac)
    human_string[32] === 32;
    for (var i = 0; i < AMOUNT_ASCII; i++) {
        human_string[33 + i] === sell_fmt.ascii[i];
    }

    // ─ (11) Line 3: "          SSSSSS" (sell symbol, right-aligned)
    //   10 leading spaces + 6 symbol bytes
    for (var i = 0; i < 10; i++) {
        human_string[48 + i] === 32;
    }
    for (var i = 0; i < SYMBOL_LEN; i++) {
        human_string[48 + 10 + i] === sell_reg.out_symbol_bytes[i];
    }

    // ─ (12) Line 4: "for at least:   " ──────────────────────────────
    //   f=102 o=111 r=114 ' '=32 a=97 t=116 ' '=32 l=108 e=101 a=97 s=115 t=116 :=58 ' ' ' ' ' '
    var LINE4[16] = [102,111,114,32,97,116,32,108,101,97,115,116,58,32,32,32];
    for (var i = 0; i < 16; i++) {
        human_string[64 + i] === LINE4[i];
    }

    // ─ (13) Line 5: " XXXXXXXXXX.YYYY" (buy amount) ────────────────
    human_string[80] === 32;
    for (var i = 0; i < AMOUNT_ASCII; i++) {
        human_string[81 + i] === buy_fmt.ascii[i];
    }

    // ─ (14) Line 6: "          SSSSSS" (buy symbol) ─────────────────
    for (var i = 0; i < 10; i++) {
        human_string[96 + i] === 32;
    }
    for (var i = 0; i < SYMBOL_LEN; i++) {
        human_string[96 + 10 + i] === buy_reg.out_symbol_bytes[i];
    }

    // ─ (15) Line 7: "                " (reserved, all spaces) ──────
    for (var i = 0; i < 16; i++) {
        human_string[112 + i] === 32;
    }
}

component main {public [H_tx, H_str, H_root]} = Eip712OrderProof();
