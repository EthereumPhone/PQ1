pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// circuits/lib/merkle_erc20_registry.circom — Poseidon-Merkle ERC20 lookup
// ─────────────────────────────────────────────────────────────────────
//
// Replacement for the hardcoded 8-token table in `erc20_registry.circom`.
// The caller supplies an address (as 20 raw canonical bytes) plus a
// witness that claims "(chain_id, address) matches this entry, with
// symbol S and decimals D, and here's a Merkle inclusion proof". The
// circuit hashes the leaf with Poseidon6, walks the proof with
// Poseidon2, and constrains the final root against the public signal
// `root` (the third public input to the parent circuit, tied to the
// firmware's compile-time `ERC20_POSEIDON_ROOT` constant).
//
// The tree covers the same `(chain_id, contract)` entry set as the
// SHA-256 ERC-20 metadata DB that `dbgen` writes — see
// `dbgen/src/erc20_poseidon.rs::canonical_erc20_poseidon_leaf` for the
// matching host-side leaf layout. Both sides hash a 6-field leaf:
//
//   f0 = chain_id                                  (u64 — small scalar)
//   f1 = address packed big-endian into u160
//   f2 = decimals                                  (u8)
//   f3 = symbol packed BE, right-padded with 0x20 to SYMBOL_LEN chars
//   f4 = symbol_len
//   f5 = 0                                         (reserved)
//
// ## Why a bespoke binary tree instead of SMTVerifier
//
// circomlib ships a generic `SMTVerifier` in `circuits/smt/`, but it's
// designed for sparse, key/value leaves and carries insertion /
// exclusion semantics we don't need. A fixed-depth binary Poseidon
// tree checker is cheaper (~80 constraints/level) and easier to keep
// byte-compatible with the `dbgen` host-side tree.
//
// ## Outputs
//
//   decimals        : passed through from witness
//   scale_factor    : 10^(MAX_DECIMALS - decimals) (muxed from a
//                     compile-time LUT on decimals ∈ [0..MAX_DECIMALS])
//   symbol[SYMBOL]  : the actual ASCII bytes the caller can splice
//                     into its display string
//   symbol_len      : passed through from witness
//   ok              : 1 iff leaf hashes correctly AND walks the proof
//                     to the supplied root AND decimals ≤ MAX_DECIMALS
//
// The caller MUST constrain `ok === 1`.

include "../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

// SymbolPackBE(SYMBOL_LEN)
//
// Pack up to SYMBOL_LEN raw ASCII bytes into a single field element,
// right-padded with 0x20 (ASCII space). The left-most byte is the
// most-significant in the packed field; shorter symbols place their
// bytes at the top and fill the low-order slots with spaces.
//
// Witness convention: `symbol_bytes[0..symbol_len)` are the real
// bytes, `symbol_bytes[symbol_len..SYMBOL_LEN)` MUST be 0x20. The
// template enforces this by range-checking symbol_len and computing
// the packed value over SYMBOL_LEN bytes unconditionally.
template SymbolPackBE(SYMBOL_LEN) {
    signal input  symbol_bytes[SYMBOL_LEN];
    signal input  symbol_len;
    signal output packed;
    signal output ok;

    // Range-check symbol_len ∈ [1, SYMBOL_LEN].
    component len_lt = LessThan(8);
    len_lt.in[0] <== symbol_len;
    len_lt.in[1] <== SYMBOL_LEN + 1;
    signal len_in_range;
    len_in_range <== len_lt.out;

    component len_gt = GreaterThan(8);
    len_gt.in[0] <== symbol_len;
    len_gt.in[1] <== 0;
    signal len_nonzero;
    len_nonzero <== len_gt.out;

    // Each byte must be in [0x20, 0x7e]. 0x20 doubles as the right-pad
    // character so trailing spaces trivially satisfy the range check.
    component byte_ge[SYMBOL_LEN];
    component byte_lt[SYMBOL_LEN];
    signal byte_ok[SYMBOL_LEN];
    signal byte_ok_acc[SYMBOL_LEN + 1];
    byte_ok_acc[0] <== 1;
    for (var i = 0; i < SYMBOL_LEN; i++) {
        byte_ge[i] = GreaterEqThan(8);
        byte_ge[i].in[0] <== symbol_bytes[i];
        byte_ge[i].in[1] <== 32;
        byte_lt[i] = LessThan(8);
        byte_lt[i].in[0] <== symbol_bytes[i];
        byte_lt[i].in[1] <== 127;
        byte_ok[i] <== byte_ge[i].out * byte_lt[i].out;
        byte_ok_acc[i + 1] <== byte_ok_acc[i] * byte_ok[i];
    }

    // Pack big-endian: packed = sum_{i<SYMBOL_LEN} symbol_bytes[i] * 256^(SYMBOL_LEN - 1 - i)
    signal acc[SYMBOL_LEN + 1];
    acc[0] <== 0;
    for (var i = 0; i < SYMBOL_LEN; i++) {
        acc[i + 1] <== acc[i] * 256 + symbol_bytes[i];
    }
    packed <== acc[SYMBOL_LEN];

    // Trailing-padding rule: for every slot i ≥ symbol_len, symbol_bytes[i]
    // must be exactly 0x20 (space). We enforce this bit-by-bit via a
    // cumulative "past-end" selector.
    //
    //   past_end[i] = 1 iff i >= symbol_len
    //
    // Implemented via `GreaterEqThan`, and the pad check becomes
    // `past_end[i] * (symbol_bytes[i] - 32) === 0`.
    component past[SYMBOL_LEN];
    signal pad_check[SYMBOL_LEN];
    component pad_isz[SYMBOL_LEN];
    signal pad_ok_acc[SYMBOL_LEN + 1];
    pad_ok_acc[0] <== 1;
    for (var i = 0; i < SYMBOL_LEN; i++) {
        past[i] = GreaterEqThan(8);
        past[i].in[0] <== i;
        past[i].in[1] <== symbol_len;
        pad_check[i] <== past[i].out * (symbol_bytes[i] - 32);
        pad_isz[i] = IsZero();
        pad_isz[i].in <== pad_check[i];
        pad_ok_acc[i + 1] <== pad_ok_acc[i] * pad_isz[i].out;
    }

    signal range_ok;
    range_ok <== len_in_range * len_nonzero;
    signal inner_ok;
    inner_ok <== range_ok * byte_ok_acc[SYMBOL_LEN];
    ok <== inner_ok * pad_ok_acc[SYMBOL_LEN];
}

// AddressPackBE(20)
//
// Pack a 20-byte address (big-endian in the canonical buffer) into a
// single field element. The caller hands in the canonical slice
// directly (no copy), so this just folds bytes into a running
// base-256 accumulator.
template AddressPackBE() {
    signal input  bytes[20];
    signal output packed;

    signal acc[21];
    acc[0] <== 0;
    for (var i = 0; i < 20; i++) {
        acc[i + 1] <== acc[i] * 256 + bytes[i];
    }
    packed <== acc[20];
}

// ScaleFactorLut(MAX_DECIMALS)
//
// Compile-time 19-entry lookup table for `scale_factor = 10^(MAX_DEC
// - decimals)`. `decimals` is the prover-supplied witness and must be
// in `[0, MAX_DECIMALS]`. The mux is implemented as a one-hot
// dot-product.
template ScaleFactorLut(MAX_DECIMALS) {
    signal input  decimals;
    signal output scale_factor;
    signal output ok;

    // Range: 0 ≤ decimals ≤ MAX_DECIMALS.
    component range = LessThan(8);
    range.in[0] <== decimals;
    range.in[1] <== MAX_DECIMALS + 1;
    signal in_range;
    in_range <== range.out;

    // Build 10^(MAX_DECIMALS - d) for d in 0..=MAX_DECIMALS.
    var pow10[MAX_DECIMALS + 1];
    var cur = 1;
    // pow10[MAX_DECIMALS] = 1 (d=MAX → 10^0)
    // pow10[MAX_DECIMALS-1] = 10 (d=MAX-1 → 10^1)
    // ...
    // pow10[0] = 10^MAX_DECIMALS
    pow10[MAX_DECIMALS] = 1;
    for (var k = 1; k <= MAX_DECIMALS; k++) {
        cur = cur * 10;
        pow10[MAX_DECIMALS - k] = cur;
    }

    // One-hot selector: sel[i] = 1 iff decimals == i.
    component eqs[MAX_DECIMALS + 1];
    signal sel[MAX_DECIMALS + 1];
    for (var i = 0; i <= MAX_DECIMALS; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== decimals - i;
        sel[i] <== eqs[i].out;
    }

    // Mux dot-product over the LUT.
    signal acc[MAX_DECIMALS + 2];
    acc[0] <== 0;
    for (var i = 0; i <= MAX_DECIMALS; i++) {
        acc[i + 1] <== acc[i] + sel[i] * pow10[i];
    }
    scale_factor <== acc[MAX_DECIMALS + 1];

    ok <== in_range;
}

// Poseidon2 — arity-2 Poseidon wrapper for binary Merkle tree nodes.
// Directly uses `Poseidon255(2)` from the bls12381-circom package;
// this alias exists only to make the downstream Merkle-walk code read
// more naturally.
template Poseidon2Node() {
    signal input  left;
    signal input  right;
    signal output hash;

    component h = Poseidon255(2);
    h.in[0] <== left;
    h.in[1] <== right;
    hash <== h.out;
}

// MerkleErc20Registry(TREE_HEIGHT, SYMBOL_LEN, MAX_DECIMALS)
//
// Witness inputs (provided by the prover):
//   address_bytes[20]    : the canonical address slice this lookup is
//                          bound to — shared with the parent circuit
//   chain_id             : scalar, matches the canonical chain_id slot
//   decimals             : scalar, prover-supplied from the off-device tree
//   symbol_bytes[SYMBOL_LEN]
//                        : ASCII, right-padded with 0x20
//   symbol_len           : scalar in [1..SYMBOL_LEN]
//   path_sel[TREE_HEIGHT]: 0 = we're the LEFT child (sibling goes right),
//                          1 = RIGHT child (sibling goes left). MUST
//                          equal bit-i of `leaf_idx` in the host tree.
//   siblings[TREE_HEIGHT]: the Merkle path, leaf-up
//
// Parent-provided:
//   root                 : Poseidon Merkle root (public input; tied to
//                          `ERC20_POSEIDON_ROOT` at firmware-verify time)
//
// Outputs:
//   decimals, scale_factor, symbol_bytes (pass-through), symbol_len, ok.
//
// The parent circuit MUST constrain `ok === 1` AND also constrain the
// `address_bytes` input against the matching slice of its canonical.
template MerkleErc20Registry(TREE_HEIGHT, SYMBOL_LEN, MAX_DECIMALS) {
    signal input  address_bytes[20];
    signal input  chain_id;
    signal input  decimals;
    signal input  symbol_bytes[SYMBOL_LEN];
    signal input  symbol_len;
    signal input  path_sel[TREE_HEIGHT];
    signal input  siblings[TREE_HEIGHT];
    signal input  root;

    signal output out_decimals;
    signal output scale_factor;
    signal output out_symbol_bytes[SYMBOL_LEN];
    signal output out_symbol_len;
    signal output ok;

    // ── 1. Pack address bytes into f1 ───────────────────────────────
    component addr_pack = AddressPackBE();
    for (var i = 0; i < 20; i++) {
        addr_pack.bytes[i] <== address_bytes[i];
    }

    // ── 2. Pack symbol bytes into f3, range-check + pad-check ──────
    component sym_pack = SymbolPackBE(SYMBOL_LEN);
    for (var i = 0; i < SYMBOL_LEN; i++) {
        sym_pack.symbol_bytes[i] <== symbol_bytes[i];
    }
    sym_pack.symbol_len <== symbol_len;

    // ── 3. Hash the 6-field leaf ────────────────────────────────────
    //        Poseidon6(chain_id, address, decimals, symbol_packed,
    //                  symbol_len, 0)
    component leaf_h = Poseidon255(6);
    leaf_h.in[0] <== chain_id;
    leaf_h.in[1] <== addr_pack.packed;
    leaf_h.in[2] <== decimals;
    leaf_h.in[3] <== sym_pack.packed;
    leaf_h.in[4] <== symbol_len;
    leaf_h.in[5] <== 0;

    // ── 4. Walk the Merkle proof ────────────────────────────────────
    //
    // path_sel[i] is the bit of the leaf index at level i:
    //   0 → our current hash is the LEFT child at level i+1
    //   1 → our current hash is the RIGHT child at level i+1
    //
    // path_sel must be binary; enforce `s*(s-1) === 0`.
    signal cur[TREE_HEIGHT + 1];
    cur[0] <== leaf_h.out;

    component lvl_hash[TREE_HEIGHT];
    component lvl_mux_l[TREE_HEIGHT];
    component lvl_mux_r[TREE_HEIGHT];
    signal path_check[TREE_HEIGHT];
    for (var i = 0; i < TREE_HEIGHT; i++) {
        // Binarize path_sel[i].
        path_check[i] <== path_sel[i] * (path_sel[i] - 1);
        path_check[i] === 0;

        lvl_mux_l[i] = Mux1();
        lvl_mux_l[i].c[0] <== cur[i];       // s=0: L = cur
        lvl_mux_l[i].c[1] <== siblings[i];  // s=1: L = sibling
        lvl_mux_l[i].s <== path_sel[i];

        lvl_mux_r[i] = Mux1();
        lvl_mux_r[i].c[0] <== siblings[i];  // s=0: R = sibling
        lvl_mux_r[i].c[1] <== cur[i];       // s=1: R = cur
        lvl_mux_r[i].s <== path_sel[i];

        lvl_hash[i] = Poseidon2Node();
        lvl_hash[i].left  <== lvl_mux_l[i].out;
        lvl_hash[i].right <== lvl_mux_r[i].out;
        cur[i + 1] <== lvl_hash[i].hash;
    }

    // ── 5. Root equality ────────────────────────────────────────────
    component root_isz = IsZero();
    root_isz.in <== cur[TREE_HEIGHT] - root;
    signal root_ok;
    root_ok <== root_isz.out;

    // ── 6. Scale factor LUT ─────────────────────────────────────────
    component lut = ScaleFactorLut(MAX_DECIMALS);
    lut.decimals <== decimals;

    // ── 7. Wire outputs + ok ────────────────────────────────────────
    out_decimals <== decimals;
    scale_factor <== lut.scale_factor;
    for (var i = 0; i < SYMBOL_LEN; i++) {
        out_symbol_bytes[i] <== symbol_bytes[i];
    }
    out_symbol_len <== symbol_len;

    signal ok_ab;
    ok_ab <== sym_pack.ok * lut.ok;
    ok <== ok_ab * root_ok;
}
