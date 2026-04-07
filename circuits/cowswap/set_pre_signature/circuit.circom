pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// CowSwap setPreSignature clear-signing circuit
// Written in-tree (NOT imported from an upstream). Reuses ABI
// primitives from circuits/aave_v3/abi_primitives.circom, which were
// imported from github.com/ZKNoxHQ/ZKlarity@5e8b3f9 — see
// circuits/UPSTREAM.md for provenance and license caveats. The
// primitives file carries the same unresolved-license note; treat
// this circuit as covered by the same caveat for as long as it
// includes that file.
// ─────────────────────────────────────────────────────────────────────
//

include "../../aave_v3/abi_primitives.circom";
include "../../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/*
 * CowSwap GPv2Settlement.setPreSignature(bytes orderUid, bool signed)
 * ─────────────────────────────────────────────────────────────────
 *
 * Calldata layout (164 bytes, identical overall size to Aave borrow):
 *
 *   offset  size  field
 *   ──────  ────  ─────
 *        0     4  selector      = 0xec6cb13f
 *        4    32  bytes offset  = 0x40 (32-byte big-endian)
 *       36    32  bool signed   = 0 or 1 (32-byte big-endian)
 *       68    32  bytes length  = 56 (orderUid length)
 *      100    64  bytes data    = orderUid (56 B) + 8 B zero padding
 *   ───────
 *      164    total
 *
 * The CowSwap orderUid itself is 56 bytes:
 *   orderUid[0..32]  = orderDigest (keccak256 of the GPv2Order struct)
 *   orderUid[32..52] = owner (20-byte address)
 *   orderUid[52..56] = validTo (uint32 big-endian)
 *
 * This circuit does NOT decode the orderUid contents any further —
 * it treats the 56 bytes as an opaque blob whose integrity is bound
 * via the calldata-wide Poseidon hash. A richer follow-up could
 * format orderDigest / owner / validTo into the readable string for
 * a full human-readable preview.
 *
 * Binding constraints:
 *   (1) Poseidon255(calldata) == H_tx
 *   (2) selector == 0xec6cb13f
 *   (3) ABI bytes offset == 0x40
 *   (4) bool signed == 1 (we only clear-sign the "approve" direction;
 *                         revocations take a different UX path)
 *   (5) ABI bytes length == 56
 *   (6) zero-padding bytes [156..164) == 0x00
 *   (7) readable == "Pre-sign CowSwap order" (22 ASCII bytes, rest 0x00)
 *   (8) Poseidon255(readable) == H_str
 *
 * The readable string is static for now: any valid setPreSignature call
 * with signed=1 maps to the same string. This is deliberately minimal
 * — the goal of M3 is to prove the in-tree toolchain builds a new
 * protocol's VK end-to-end, not to ship production UX for CowSwap.
 * A richer version with orderDigest hex formatting is a follow-up.
 */

// ─────────────────────────────────────────────────────────────────────
// PackBytes31 / PoseidonBytes — duplicated from upstream
// circuits/aave_v3/clear_signing_proof.circom because that file's
// `component main = ClearSigningProof();` block prevents us from
// `include`ing it here. A future refactor should lift these into
// a shared `circuits/lib/poseidon_bytes.circom` and `include` it
// from both roots.
// ─────────────────────────────────────────────────────────────────────

template CsPackBytes31(N_BLOCKS) {
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

template CsPoseidonBytes(N_BYTES) {
    var N_BLOCKS = (N_BYTES + 30) \ 31;   // ceil division
    var PADDED   = N_BLOCKS * 31;

    signal input  bytes[N_BYTES];
    signal output hash;

    signal padded[PADDED];
    for (var i = 0; i < N_BYTES; i++)  padded[i] <== bytes[i];
    for (var i = N_BYTES; i < PADDED; i++) padded[i] <== 0;

    component pack = CsPackBytes31(N_BLOCKS);
    for (var i = 0; i < PADDED; i++) pack.bytes[i] <== padded[i];

    component h = Poseidon255(N_BLOCKS);
    for (var i = 0; i < N_BLOCKS; i++) h.in[i] <== pack.fields[i];

    hash <== h.out;
}

// ─────────────────────────────────────────────────────────────────────
// SetPreSignatureProof — root template
// ─────────────────────────────────────────────────────────────────────

template SetPreSignatureProof() {
    var MAX_CALLDATA = 164;
    var STRING_LEN   = 64;

    // ══ PUBLIC signals ═══════════════════════════════════════════════
    signal input  H_tx;
    signal input  H_str;

    // ══ PRIVATE signals (witness) ════════════════════════════════════
    signal input  calldata[MAX_CALLDATA];
    signal input  human_string[STRING_LEN];

    // ─ (1) Poseidon255(calldata) == H_tx ─────────────────────────────
    component h_tx = CsPoseidonBytes(MAX_CALLDATA);
    for (var i = 0; i < MAX_CALLDATA; i++) h_tx.bytes[i] <== calldata[i];
    h_tx.hash === H_tx;

    // ─ (2) selector == 0xec6cb13f ────────────────────────────────────
    component sel = SelectorCheck(0xec, 0x6c, 0xb1, 0x3f);
    for (var i = 0; i < 4; i++) sel.calldata_bytes[i] <== calldata[i];
    sel.ok === 1;

    // ─ (3) ABI bytes offset at slot 0 (calldata[4..36]) must be 0x40.
    //       The ABI encodes offsets as 32-byte big-endian, so:
    //         calldata[4..35] == 0x00  (31 bytes of padding)
    //         calldata[35]    == 0x40
    component off_pad = AllZeroBytes(31);
    for (var i = 0; i < 31; i++) off_pad.bytes[i] <== calldata[4 + i];
    off_pad.ok === 1;
    calldata[35] === 0x40;

    // ─ (4) bool signed == 1 at slot 1 (calldata[36..68])
    //       ABI bool encoding = 32-byte big-endian uint256 valued 0 or 1
    component signed_pad = AllZeroBytes(31);
    for (var i = 0; i < 31; i++) signed_pad.bytes[i] <== calldata[36 + i];
    signed_pad.ok === 1;
    calldata[67] === 1;

    // ─ (5) bytes length == 56 at slot 2 (calldata[68..100])
    component len_pad = AllZeroBytes(31);
    for (var i = 0; i < 31; i++) len_pad.bytes[i] <== calldata[68 + i];
    len_pad.ok === 1;
    calldata[99] === 56;

    // ─ (6) zero-padding [156..164): the last 8 bytes of the calldata
    //       are the bytes-padding of the 56-byte orderUid up to
    //       64 bytes (32-byte multiple). They must be 0x00.
    component tail_pad = AllZeroBytes(8);
    for (var i = 0; i < 8; i++) tail_pad.bytes[i] <== calldata[156 + i];
    tail_pad.ok === 1;

    // Note: we do NOT further constrain calldata[100..156) (the 56
    // actual orderUid bytes). Those are bound via Poseidon(calldata)
    // but their internal structure is not decoded by this circuit.

    // ─ (7) readable == "Pre-sign CowSwap order" + 42 zero bytes ──────
    //       ASCII: 'P'=80 'r'=114 'e'=101 '-'=45 's'=115 'i'=105 'g'=103
    //              'n'=110 ' '=32 'C'=67 'o'=111 'w'=119 'S'=83 'w'=119
    //              'a'=97 'p'=112 'o'=111 'r'=114 'd'=100 'e'=101 'r'=114
    //       "Pre-sign CowSwap order" = 22 bytes
    var STATIC_READABLE[22] = [
        80, 114, 101,  45, 115, 105, 103, 110,  32,  67, 111, 119,
        83, 119,  97, 112,  32, 111, 114, 100, 101, 114
    ];
    for (var i = 0; i < 22; i++) {
        human_string[i] === STATIC_READABLE[i];
    }
    for (var i = 22; i < STRING_LEN; i++) {
        human_string[i] === 0;
    }

    // ─ (8) Poseidon255(human_string) == H_str ────────────────────────
    component h_str = CsPoseidonBytes(STRING_LEN);
    for (var i = 0; i < STRING_LEN; i++) h_str.bytes[i] <== human_string[i];
    h_str.hash === H_str;
}

component main {public [H_tx, H_str]} = SetPreSignatureProof();
