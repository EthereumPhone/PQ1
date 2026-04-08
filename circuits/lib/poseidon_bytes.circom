pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// circuits/lib/poseidon_bytes.circom — shared Poseidon-over-bytes
// ─────────────────────────────────────────────────────────────────────
//
// Lifted out of circuits/aave_v3/clear_signing_proof.circom and the
// per-protocol duplicates that used to live in
// circuits/cowswap/{set_pre_signature,eip712_order}/circuit.circom.
// Any new clear-signing circuit should `include` this file instead of
// pasting the templates again under a unique name prefix.
//
// Why a separate file: `clear_signing_proof.circom` ends with a
// `component main = ClearSigningProof();` line, which makes it
// un-includeable from another circuit (every `component main` clause
// in the include chain becomes ambiguous). This file deliberately
// has NO `component main`, so it can be `include`d freely.
//
// The names here are unprefixed (`PoseidonBytes`, `PackBytes31`)
// because there is exactly one canonical implementation now. The
// historical Aave copy in clear_signing_proof.circom is left in
// place for two reasons:
//   (1) the committed circuits/aave_v3/circuit_final.zkey pins those
//       templates, so refactoring them would force a new trusted
//       setup ceremony;
//   (2) the historical CowSwap setPreSignature circuit shares the
//       same situation via its own committed zkey.
// This file is the source of truth for any *new* circuit.

include "../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";

// PackBytes31(N_BLOCKS) — pack N_BLOCKS × 31 raw bytes into N_BLOCKS
// field elements (31 bytes × 8 = 248 bits, comfortably under the
// BLS12-381 / BN254 254-bit prime). Each block is packed big-endian.
template PackBytes31(N_BLOCKS) {
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

// PoseidonBytes(N_BYTES) — Poseidon hash of N_BYTES raw bytes,
// zero-padded to a multiple of 31 and packed into N_BLOCKS field
// elements before being fed through Poseidon255(N_BLOCKS).
template PoseidonBytes(N_BYTES) {
    var N_BLOCKS = (N_BYTES + 30) \ 31;   // ceil division
    var PADDED   = N_BLOCKS * 31;

    signal input  bytes[N_BYTES];
    signal output hash;

    signal padded[PADDED];
    for (var i = 0; i < N_BYTES; i++)      padded[i] <== bytes[i];
    for (var i = N_BYTES; i < PADDED; i++) padded[i] <== 0;

    component pack = PackBytes31(N_BLOCKS);
    for (var i = 0; i < PADDED; i++) pack.bytes[i] <== padded[i];

    component h = Poseidon255(N_BLOCKS);
    for (var i = 0; i < N_BLOCKS; i++) h.in[i] <== pack.fields[i];

    hash <== h.out;
}
