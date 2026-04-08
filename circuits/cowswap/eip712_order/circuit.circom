pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// CowSwap EIP-712 GPv2Order clear-signing circuit (M4)
//
// Written in-tree. Reuses ABI primitives from
// circuits/aave_v3/abi_primitives.circom — see circuits/UPSTREAM.md for
// the provenance / license caveat that propagates to this file.
// ─────────────────────────────────────────────────────────────────────
//
// What this circuit proves
// ────────────────────────
// Given a 164-byte canonical packed GPv2Order encoding and a 64-byte
// human-readable string, the proof attests:
//
//   (1) Poseidon255(canonical, 164) === H_order
//   (2) Poseidon255(readable,  64)  === H_str
//   (3) The two are linked by a deterministic format function:
//
//       readable[ 0.. 8) = "CowSwap "
//       readable[ 8..12) = "SELL"  if canonical[160] == 0
//                          "BUY "  if canonical[160] == 1
//       readable[12..16) = "    "
//       readable[16..22) = "exp 0x"
//       readable[22..30) = ASCII upper-hex of canonical[156..160)
//                          (the 4-byte big-endian validTo field)
//       readable[30..32) = "  "
//       readable[32..64) = 0x00 (null padding)
//
//       canonical[160] (kind) is constrained to {0, 1}
//       canonical[161] (partiallyFillable) is unconstrained here — the
//         secure world enforces a {0, 1} range when it decodes the
//         struct for the EIP-712 keccak digest.
//
// What this circuit DOES NOT do
// ─────────────────────────────
// It does not decode token symbols, format amounts, or display fee /
// receiver / appData fields. The full set of 12 GPv2Order fields is
// only bound implicitly: every byte of `canonical` participates in
// `Poseidon(canonical)` and therefore the secure world (which
// independently re-keccaks the same buffer) cannot substitute any
// field without breaking the proof. The SECURE world is what
// reconstructs the EIP-712 abi.encode struct + computes the digest
// the user actually signs; the circuit's only job is to bind a
// simple, human-readable summary of the order's KIND and EXPIRY to
// those bytes so the trusted UI display is non-trivially attested.
//
// A v2 of this circuit can grow `canonical` to 217 bytes (poseidon7,
// requires extending the firmware Poseidon footprint by one
// instance) and use the extra 53 bytes for `appData`, OR add a token
// registry / amount formatter the way the Aave V3 circuit does. For
// now, M4 ships the minimum viable EIP-712 binding so the firmware
// dispatch path + native keccak digest computation can be
// end-to-end verified.

include "../../aave_v3/abi_primitives.circom";
include "../../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

// ─────────────────────────────────────────────────────────────────────
// PoseidonBytes / PackBytes31 — duplicated from
// circuits/aave_v3/clear_signing_proof.circom because that file's
// `component main = ClearSigningProof();` line prevents includes.
// Same trick as cowswap/set_pre_signature/circuit.circom (M3).
// ─────────────────────────────────────────────────────────────────────

template EipPackBytes31(N_BLOCKS) {
    var TOTAL_BYTES = N_BLOCKS * 31;

    signal input  bytes[TOTAL_BYTES];
    signal output fields[N_BLOCKS];

    signal acc[N_BLOCKS][32];
    for (var b = 0; b < N_BLOCKS; b++) {
        acc[b][0] <== 0;
        for (var i = 0; i < 31; i++) {
            acc[b][i+1] <== acc[b][i] * 256 + bytes[b * 31 + i];
        }
        fields[b] <== acc[b][31];
    }
}

template EipPoseidonBytes(N_BYTES) {
    var N_BLOCKS = (N_BYTES + 30) \ 31;
    var PADDED   = N_BLOCKS * 31;

    signal input  bytes[N_BYTES];
    signal output hash;

    signal padded[PADDED];
    for (var i = 0; i < N_BYTES; i++) padded[i] <== bytes[i];
    for (var i = N_BYTES; i < PADDED; i++) padded[i] <== 0;

    component pack = EipPackBytes31(N_BLOCKS);
    for (var i = 0; i < PADDED; i++) pack.bytes[i] <== padded[i];

    component h = Poseidon255(N_BLOCKS);
    for (var i = 0; i < N_BLOCKS; i++) h.in[i] <== pack.fields[i];

    hash <== h.out;
}

// ─────────────────────────────────────────────────────────────────────
// HexNibble : map a 4-bit value n in [0,15] to its uppercase ASCII
//             hex character: 0..9 → '0'..'9' (48..57), 10..15 → 'A'..'F' (65..70).
//
// Constraint: requires `nibble` already in [0,15] (caller bit-decomposes).
// Implementation:
//   is_dec = LessThan(4)(nibble, 10)         // 1 iff nibble < 10
//   ascii  = is_dec * (nibble + 48) + (1 - is_dec) * (nibble + 55)
// ─────────────────────────────────────────────────────────────────────
template HexNibble() {
    signal input  nibble;
    signal output ascii;

    component lt = LessThan(4);
    lt.in[0] <== nibble;
    lt.in[1] <== 10;

    signal is_dec;
    is_dec <== lt.out;

    signal dec_part;   // is_dec * (nibble + 48)
    signal hex_part;   // (1 - is_dec) * (nibble + 55)
    signal one_minus_dec;
    one_minus_dec <== 1 - is_dec;

    dec_part <== is_dec * (nibble + 48);
    hex_part <== one_minus_dec * (nibble + 55);

    ascii <== dec_part + hex_part;
}

// ─────────────────────────────────────────────────────────────────────
// ByteToHexAscii : split a byte into two ASCII upper-hex chars.
// ─────────────────────────────────────────────────────────────────────
template ByteToHexAscii() {
    signal input  byte;
    signal output hi_ascii;
    signal output lo_ascii;

    // Decompose byte into two 4-bit nibbles. We constrain the
    // recomposition (byte === hi*16 + lo) and additionally
    // bit-decompose hi and lo with Num2Bits(4) to enforce the [0,15]
    // range — the LessThan inside HexNibble already needs that.
    signal hi;
    signal lo;
    hi <-- byte \ 16;
    lo <-- byte - 16 * hi;
    byte === hi * 16 + lo;

    component hi_bits = Num2Bits(4);
    hi_bits.in <== hi;
    component lo_bits = Num2Bits(4);
    lo_bits.in <== lo;

    component hi_h = HexNibble();
    hi_h.nibble <== hi;
    component lo_h = HexNibble();
    lo_h.nibble <== lo;

    hi_ascii <== hi_h.ascii;
    lo_ascii <== lo_h.ascii;
}

// ─────────────────────────────────────────────────────────────────────
// Eip712OrderProof — root template
// ─────────────────────────────────────────────────────────────────────
template Eip712OrderProof() {
    var CANONICAL_LEN = 164;
    var STRING_LEN    = 64;

    // ══ PUBLIC signals ══════════════════════════════════════════════
    signal input H_tx;     // = Poseidon(canonical, 164)  — kept the same
    signal input H_str;    //   public-signal name (`H_tx`) as the M3
                           //   circuit so the existing 2-IC Groth16
                           //   verifier and bindings work unchanged.

    // ══ PRIVATE signals (witness) ═══════════════════════════════════
    signal input canonical[CANONICAL_LEN];
    signal input human_string[STRING_LEN];

    // ─ (1) Poseidon(canonical) === H_tx ─────────────────────────────
    component h_tx = EipPoseidonBytes(CANONICAL_LEN);
    for (var i = 0; i < CANONICAL_LEN; i++) h_tx.bytes[i] <== canonical[i];
    h_tx.hash === H_tx;

    // ─ (2) Poseidon(human_string) === H_str ─────────────────────────
    component h_str = EipPoseidonBytes(STRING_LEN);
    for (var i = 0; i < STRING_LEN; i++) h_str.bytes[i] <== human_string[i];
    h_str.hash === H_str;

    // ─ (3) kind byte ∈ {0, 1} ───────────────────────────────────────
    signal kind;
    kind <== canonical[160];
    // kind * (kind - 1) === 0 enforces kind ∈ {0, 1}.
    signal kind_check;
    kind_check <== kind * (kind - 1);
    kind_check === 0;

    // ─ (4) readable[0..8) === "CowSwap "  (literal ASCII) ──────────
    var PREFIX[8] = [67, 111, 119, 83, 119, 97, 112, 32];
    for (var i = 0; i < 8; i++) {
        human_string[i] === PREFIX[i];
    }

    // ─ (5) readable[8..12) === "SELL" or "BUY " ─────────────────────
    //       Selected by `kind`: 0 → SELL, 1 → BUY .
    //       For each of the 4 ASCII bytes, mux:
    //         expected = SELL[i] + kind * (BUY[i] - SELL[i])
    var SELL[4] = [83, 69, 76, 76];   // 'S','E','L','L'
    var BUY [4] = [66, 85, 89, 32];   // 'B','U','Y',' '
    signal kind_expected[4];
    for (var i = 0; i < 4; i++) {
        kind_expected[i] <== SELL[i] + kind * (BUY[i] - SELL[i]);
        human_string[8 + i] === kind_expected[i];
    }

    // ─ (6) readable[12..16) === "    "  (4 spaces) ──────────────────
    for (var i = 0; i < 4; i++) {
        human_string[12 + i] === 32;
    }

    // ─ (7) readable[16..22) === "exp 0x" ────────────────────────────
    var EXP_PREFIX[6] = [101, 120, 112, 32, 48, 120];   // 'e','x','p',' ','0','x'
    for (var i = 0; i < 6; i++) {
        human_string[16 + i] === EXP_PREFIX[i];
    }

    // ─ (8) readable[22..30) = ASCII upper-hex of canonical[156..160)
    //       (4 bytes of validTo, big-endian → 8 hex chars)
    component to_hex[4];
    for (var i = 0; i < 4; i++) {
        to_hex[i] = ByteToHexAscii();
        to_hex[i].byte <== canonical[156 + i];
        human_string[22 + i * 2]     === to_hex[i].hi_ascii;
        human_string[22 + i * 2 + 1] === to_hex[i].lo_ascii;
    }

    // ─ (9) readable[30..32) === "  " ────────────────────────────────
    human_string[30] === 32;
    human_string[31] === 32;

    // ─ (10) readable[32..64) === 0 ──────────────────────────────────
    for (var i = 32; i < STRING_LEN; i++) {
        human_string[i] === 0;
    }
}

component main {public [H_tx, H_str]} = Eip712OrderProof();
