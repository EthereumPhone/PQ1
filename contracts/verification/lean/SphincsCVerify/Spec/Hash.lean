/-
SHA-256-based tweakable hash primitives for SPHINCS+C10.

Every function in this module corresponds byte-for-byte to:
  * `sphincs-c10/src/hash.rs` (Rust reference / firmware path)
  * `SPHINCsC10Asm.sol` (Solidity / on-chain verifier, calling the
    SHA-256 precompile at address 0x02).

## SHA-256 modeling strategy

We declare `sha256` as an `opaque` function with two postconditions:

  1. `output size = 32 bytes` — pure functional property; trivially used
     everywhere `truncate16` is called.
  2. `behaviour matches FIPS 180-4` — left as an explicit axiom in
     `Crypto/Assumptions.lean`. We never need to reduce `sha256` to a
     concrete digest inside a Lean proof; we only ever use it through
     its algebraic properties (collision-resistance, SM-TCR,
     interleaved target-subset resilience for the tweakable-hash
     construction).

This is the same strategy Verity takes for `keccak256` in
`Compiler/Keccak/Sponge.lean`: model the primitive as opaque, surface a
proven `keccak256_memory_slice_matches_evm` bridge to the EVM precompile.
For our verifier the analogous bridge is "EVM precompile 0x02 implements
FIPS 180-4 SHA-256," documented in `Bridge/Refinement.lean`.

## Why no concrete SHA-256 implementation in Lean?

A kernel-computable SHA-256 spec (à la VST/Coq SHA-256 by Appel) would
allow `decide`-style discharge of concrete test-vector cases inside Lean.
This is on the roadmap (see §3.5 of `how_to_math_proof_secureness.md`)
and would be roughly a 1-3 person-month effort; the structural pattern
to follow is Verity's `Compiler/Keccak/Sponge.lean`. For the present
deliverable we stop at the abstract spec because all our theorems are
*algebraic* (functional correctness, refinement, EUF-CMA) and do not
require executing the hash on a specific bit pattern inside the kernel.

Differential cross-checking against concrete digests is done outside
Lean, via the existing `c10_test_vectors.json` corpus in
`sphincs-c10/tests/`.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Params
import SphincsCVerify.Spec.Adrs

namespace SphincsCVerify.Spec

open ByteVec

/-! ## The abstract SHA-256 primitive

We accept a list of byte vectors and produce a 32-byte digest. Modelling
SHA-256 as `List ByteSegment → ByteVec 32` rather than `ByteVec n → ByteVec 32`
lets us state the byte-level concatenation properties without committing
to a particular size. The list shape mirrors the `Sha256::update` API
the Rust signer uses.
-/

/-- A polymorphic byte segment — exists at the spec level just to drop
    the size dependence from inputs to `sha256`. -/
structure ByteSeg where
  size : Nat
  bytes : ByteVec size

namespace ByteSeg

/-- Coerce a fixed-length byte vector to a `ByteSeg`. -/
@[inline]
def ofByteVec {n : Nat} (v : ByteVec n) : ByteSeg :=
  ⟨n, v⟩

end ByteSeg

/-- We need an `Inhabited` instance for `ByteVec 32` to declare
    `opaque sha256` — the kernel materialises an arbitrary default that
    `sha256` is then *constrained* by axioms to depart from. The
    instance carries no behavioural content. -/
instance : Inhabited (ByteVec 32) :=
  ⟨zero 32⟩

/-- Opaque SHA-256: takes a (length-erased) list of byte segments,
    returns the 32-byte digest. The actual implementation is FIPS 180-4;
    we treat it as a black box and reason about it via its axiomatised
    properties (see `Crypto/Assumptions.lean`). -/
opaque sha256 : List ByteSeg → ByteVec 32

/-- Apply `sha256` to a single concatenated byte vector. -/
@[inline]
def sha256_concat {n : Nat} (v : ByteVec n) : ByteVec 32 :=
  sha256 [ByteSeg.ofByteVec v]

/-! ## Tweakable hash primitives -/

/-- `th(seed, adrs, val)` — tweakable hash with one 32-byte input,
    truncated to N=16 bytes.

    `sha256(seed_b32 || adrs_b32 || val_b32)[0..N]`

    Solidity equivalent in `SPHINCsC10Asm.sol`:
    ```
      mstore(0x00, seed); mstore(0x20, adrs); mstore(0x40, val)
      staticcall(gas(), 0x02, 0x00, 0x60, OUT, 32)
      result := and(mload(OUT), N_MASK)
    ``` -/
def th (seed : ByteVec 32) (a : Adrs) (val : ByteVec 32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec a,
    ByteSeg.ofByteVec val])

/-- `th_pair(seed, adrs, left, right)` — tweakable hash with two 32-byte
    inputs.

    `sha256(seed_b32 || adrs_b32 || left_b32 || right_b32)[0..N]` -/
def thPair (seed : ByteVec 32) (a : Adrs) (left right : ByteVec 32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec a,
    ByteSeg.ofByteVec left,
    ByteSeg.ofByteVec right])

/-- `th_multi(seed, adrs, vals)` — tweakable hash with `vals.length`
    16-byte inputs, each pad16'd to 32 bytes.

    `sha256(seed_b32 || adrs_b32 || pad(v0) || pad(v1) || ...)[0..N]` -/
def thMulti (seed : ByteVec 32) (a : Adrs) (vals : List (ByteVec 16)) : ByteVec 16 :=
  let header := [ByteSeg.ofByteVec seed, ByteSeg.ofByteVec a]
  let padded := vals.map fun v => ByteSeg.ofByteVec (pad16 v)
  truncate16 (sha256 (header ++ padded))

/-- `h_msg(seed, root, R, message)` — domain-separated message hash
    over 160 bytes, returning the FULL 32-byte digest (no truncation).

    `sha256(seed_b32 || root_b32 || R_b32 || message_b32 || 0xFF..FF)` -/
def hMsg
    (seed root : ByteVec 32) (r : ByteVec 32) (message : ByteVec 32)
    : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec root,
    ByteSeg.ofByteVec r,
    ByteSeg.ofByteVec message,
    ByteSeg.ofByteVec (ones 32)]

/-! ## WOTS chain hashing -/

/-- Iterative chain hash: apply `th` for `steps` iterations, starting
    from position `start_pos`. -/
def chainHash
    (seed : ByteVec 32) (a : Adrs) (val : ByteVec 16)
    (startPos steps : Nat) : ByteVec 16 :=
  let rec aux (i : Nat) (current : ByteVec 16) : ByteVec 16 :=
    match i with
    | 0 => current
    | i+1 =>
      let pos := startPos + (steps - 1 - i)  -- traverse forward
      let a' := Adrs.setChainIndex a (UInt32.ofNat pos)
      let next := th seed a' (pad16 current)
      aux i next
  aux steps val
  termination_by steps - 0

/-- WOTS digest for count-grinding.

    `sha256(seed_b32 || wotsAdrs_b32 || msgHash_b32 || count_uint256)`

    Returns the full 32-byte digest for base-w digit extraction. -/
def wotsDigest
    (seed : ByteVec 32) (wotsAdrs : Adrs)
    (msgHash : ByteVec 32) (count : UInt32) : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec wotsAdrs,
    ByteSeg.ofByteVec msgHash,
    ByteSeg.ofByteVec (u32ToB32 count)]

/-- WOTS secret-key derivation.

    `sha256(sk_seed_b32 || "wots" || layer_b4 || tree_b32 || kp_b4 || chain_b4)[0..N]` -/
def wotsSecret
    (skSeed : ByteVec 32)
    (layer : UInt32) (tree : UInt64) (kp chainIdx : UInt32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec skSeed,
    ByteSeg.ofByteVec wotsTag,
    ByteSeg.ofByteVec (ofU32BE layer),
    ByteSeg.ofByteVec (u64ToB32 tree),
    ByteSeg.ofByteVec (ofU32BE kp),
    ByteSeg.ofByteVec (ofU32BE chainIdx)])

/-- FORS secret-key derivation.

    `sha256(sk_seed_b32 || "fors" || tree_idx_b4 || leaf_idx_b4)[0..N]` -/
def forsSecret
    (skSeed : ByteVec 32) (treeIdx leafIdx : UInt32) : ByteVec 16 :=
  truncate16 (sha256 [
    ByteSeg.ofByteVec skSeed,
    ByteSeg.ofByteVec forsTag,
    ByteSeg.ofByteVec (ofU32BE treeIdx),
    ByteSeg.ofByteVec (ofU32BE leafIdx)])

/-! ## Spec-level properties (free from the `sha256` axiom block)

These lemmas only depend on the byte-arithmetic of the wrappers, not on
SHA-256 semantics. They surface invariants the verifier relies on. -/

theorem th_size (seed : ByteVec 32) (a : Adrs) (val : ByteVec 32) :
    (th seed a val).data.size = 16 := by
  exact (th seed a val).size_eq

theorem thPair_size (seed : ByteVec 32) (a : Adrs) (l r : ByteVec 32) :
    (thPair seed a l r).data.size = 16 := by
  exact (thPair seed a l r).size_eq

theorem hMsg_size (seed root r m : ByteVec 32) :
    (hMsg seed root r m).data.size = 32 := by
  exact (hMsg seed root r m).size_eq

end SphincsCVerify.Spec
