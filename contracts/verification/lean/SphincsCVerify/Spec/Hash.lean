/-
SHA-256-based tweakable hash primitives for SPHINCS+C10.

Every function in this module corresponds byte-for-byte to:
  * `sphincs-c10/src/hash.rs` (Rust reference / firmware path)
  * `SPHINCsC10Asm.sol` (Solidity / on-chain verifier, calling the
    SHA-256 precompile at address 0x02).

## SHA-256 modeling strategy

We declare `sha256` as a kernel-computable `def` whose body is the
FIPS 180-4 reference implementation in `Spec/Sha256Impl.lean`. The
function is marked `@[irreducible]` so the existing algebraic proofs
that treat `sha256` as a black box keep working without trying to
unfold a 64-round body into every tactic context.

Two consequences:

  1. NIST CAVS test vectors (`SHA-256("")`, `SHA-256("abc")`) reduce
     by `native_decide` / `unfold sha256; rfl`, giving a kernel-checked
     ground truth for the byte-level differential pipeline.
  2. The cryptographic axioms in `Crypto/Assumptions.lean` are unchanged
     — they remain abstract postulates about the *function* `sha256`,
     which now happens to coincide with FIPS 180-4. The Lean kernel
     never has to *compute* SHA-256 to verify the EUF-CMA argument;
     computability is a strict strengthening of the prior opaque-only
     treatment, and the audited axiom list of `theft_free` does not
     change (no new axioms introduced — irreducibility is enforced via
     a `@[irreducible] def`, not via `axiom`).

This is the same end-state Verity reaches for `keccak256` in
`Compiler/Keccak/Sponge.lean`: a concrete sponge body + an
`@[irreducible]` seal, plus a proven `keccak256_memory_slice_matches_evm`
bridge to the EVM precompile. For our verifier the analogous bridge is
"EVM precompile 0x02 implements FIPS 180-4 SHA-256," documented as
axiom `Bridge.precompile_0x02_is_FIPS_180_4` in `Bridge/Refinement.lean`.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Params
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Sha256Impl

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

/-- The default 32-byte vector — used by `getD`-style helpers and the
    `Inhabited` instance below. -/
instance : Inhabited (ByteVec 32) :=
  ⟨zero 32⟩

/-- Flatten a list of byte segments into a single `Array UInt8`. -/
def ByteSeg.flatten (segs : List ByteSeg) : Array UInt8 :=
  segs.foldl (init := #[]) fun acc seg => acc ++ seg.bytes.data

/-- FIPS 180-4 SHA-256, lifted to take a list of byte segments and
    return a fixed-length `ByteVec 32`.

    This is the *concrete* SHA-256 backing every tweakable-hash and
    domain-separation primitive in the SPHINCS+C10 stack. The
    `@[irreducible]` attribute on `sha256` (below) prevents the kernel
    from unfolding the 64-round body inside unrelated tactic contexts,
    so all the existing algebraic proofs (treating `sha256` as a black
    box) keep working unchanged. When you actually want to *compute* a
    concrete digest (e.g. NIST CAVS test vectors), `unfold sha256
    sha256_impl` exposes the FIPS 180-4 reference. -/
def sha256_impl (segs : List ByteSeg) : ByteVec 32 :=
  let bytes := ByteSeg.flatten segs
  let digest := Sha256Impl.sha256Bytes bytes
  ⟨digest, Sha256Impl.sha256Bytes_size bytes⟩

/-- SHA-256 over a (length-erased) list of byte segments. Returns the
    32-byte digest. Definitionally equal to `sha256_impl`, but sealed
    by `@[irreducible]` so unrelated proofs don't accidentally try to
    reduce the round function. -/
@[irreducible] def sha256 : List ByteSeg → ByteVec 32 := sha256_impl

/-- Unfolding lemma for `sha256`. Use this (or `show sha256_impl …`) in
    proofs that need to inspect the underlying FIPS 180-4 implementation,
    e.g. NIST CAVS test-vector decision proofs. -/
theorem sha256_eq_impl (segs : List ByteSeg) :
    sha256 segs = sha256_impl segs := by
  unfold sha256
  rfl

/-- Apply `sha256` to a single concatenated byte vector. -/
@[inline]
def sha256_concat {n : Nat} (v : ByteVec n) : ByteVec 32 :=
  sha256 [ByteSeg.ofByteVec v]

/-- Apply `sha256` to a single `Array UInt8`. Wraps the array in a
    `ByteSeg` of its actual size. Used by `sphincsDigest` for
    `sha256(initCode)`, `sha256(callData)`, and
    `sha256(paymasterAndData)` — fields whose lengths are not fixed at
    the type level. -/
@[inline]
def sha256OfArr (bytes : Array UInt8) : ByteVec 32 :=
  sha256 [⟨bytes.size, ⟨bytes, rfl⟩⟩]

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
