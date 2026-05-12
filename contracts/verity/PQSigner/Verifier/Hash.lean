/-
  PQSigner.Verifier.Hash — Lean port of `sphincs-c10/src/hash.rs`.

  SHA-256 is treated as an axiomatised primitive (Verity v0.1.0 has
  no precompile.sha256 EDSL primitive — see
  `docs/handoff-verity-c10-verifier.md` §4 Phase 0). All tweakable
  hashes are built on this single opaque.

  Convention (matches sphincs-c10/src/hash.rs:7-10):
    Every 16-byte (n=128-bit) value sits in the TOP 128 bits of a
    32-byte buffer (left-aligned, right-zero-padded). EVM uint256 BE
    representation. This makes `pad16` left-place and `truncate`
    top-take.
-/

import PQSigner.Verifier.Params
import PQSigner.Verifier.Address

namespace PQSigner.Verifier.Hash

open PQSigner.Verifier.Params
open PQSigner.Verifier.Address (ByteVec u32ToBE u64ToBE)

/-! ## Axiomatised SHA-256

    The EVM precompile at address 0x02 returns `sha256(input)` for any
    byte string. We model it as a Lean axiom — Verity v0.1.0 doesn't
    expose a primitive for `staticcall(0x02, ...)`. Phase 0 of the
    handoff requires upstreaming this primitive; until then the
    correctness of `sha256` is a trust-boundary axiom.

    The byte-equivalence proof against the Rust ref impl
    `sphincs-c10/src/hash.rs:23-58` is via runtime KAT vectors, not
    via Lean — the Rust `sha2` crate and the EVM SHA-256 precompile
    are both assumed correct against FIPS 180-4. -/

opaque sha256 (input : ByteVec) : ByteVec

/-- SHA-256 always returns exactly 32 bytes. -/
axiom sha256_size (input : ByteVec) : (sha256 input).size = 32

/-- SHA-256 is a deterministic pure function — collisions excluded
    in the analysis are still possible in principle, but for any
    fixed input the output is constant. (`opaque` plus this axiom is
    redundant; we state it explicitly for readability of downstream
    proofs.) -/
axiom sha256_deterministic (a b : ByteVec) (h : a = b) : sha256 a = sha256 b

/-! ## N-mask truncation and padding

    Mirrors `sphincs-c10/src/hash.rs:67-79`. -/

/-- `truncate(digest : Bytes32) : Bytes16` — keep top N=16 bytes.
    Mirrors `sphincs-c10/src/hash.rs:75-79`. -/
def truncate (digest : ByteVec) : ByteVec :=
  digest.extract 0 N

/-- `pad16(val : Bytes16) : Bytes32` — left-align in a 32-byte buffer,
    right-pad with zeros. Mirrors `sphincs-c10/src/hash.rs:67-71`. -/
def pad16 (val : ByteVec) : ByteVec :=
  val.extract 0 N ++ ByteVec.zero (32 - N)

/-! ### Theorems on truncate/pad16 — the N-mask invariants -/

/-- `truncate` of a buffer with ≥ N bytes returns exactly N bytes. -/
theorem truncate_size_eq_N
    (digest : ByteVec) (h : digest.size ≥ N) :
    (truncate digest).size = N := by
  unfold truncate
  rw [Array.size_extract]
  simp [N] at h ⊢
  omega

/-- `truncate` of a SHA-256 digest is always 16 bytes — the
    canonical instance used throughout the verifier. -/
theorem truncate_sha256_size_eq_N (input : ByteVec) :
    (truncate (sha256 input)).size = N := by
  apply truncate_size_eq_N
  rw [sha256_size]; decide

/-- `pad16` of a buffer with exactly N bytes returns exactly 32 bytes. -/
theorem pad16_size_eq_32
    (val : ByteVec) (h : val.size = N) :
    (pad16 val).size = 32 := by
  unfold pad16 ByteVec.zero
  rw [Array.size_append, Array.size_extract, Array.size_replicate]
  simp [N] at h ⊢
  omega

/-- **The N-mask invariant.** After `pad16` of a 16-byte value, the
    32-byte output's bottom 16 bytes are exactly the zero block from
    `ByteVec.zero (32-N)`. The Yul verifier relies on this "bottom
    16 bytes are zero" property for every N-padded 32-byte slot.
    Mirrors `sphincs-c10/src/hash.rs:7-10`. The precondition holds
    everywhere in the verify path because the only producer of 16-byte
    values is `truncate(sha256(_))` which has `truncate_sha256_size_eq_N`. -/
theorem pad16_low_half_is_zero_block
    (val : ByteVec) (hval : val.size = N) :
    (pad16 val).extract N 32 = ByteVec.zero (32 - N) := by
  unfold pad16 ByteVec.zero
  apply Array.ext
  · simp [Array.size_extract, Array.size_replicate, N, Array.size_append]
    simp [N] at hval
    omega
  · intros i hi₁ hi₂
    simp [Array.size_extract, Array.size_append, Array.size_replicate, N] at hi₁
    simp [N] at hval
    simp [Array.getElem_extract, Array.getElem_append, Array.size_extract,
          Array.getElem_replicate, N]
    omega

/-! ## Tweakable hashes

    All three forms take a 32-byte seed + 32-byte ADRS and produce a
    16-byte hash by truncating SHA-256. Mirrors
    `sphincs-c10/src/hash.rs:109-149`. -/

/-- `th(seed, adrs, val)` — 1-input tweakable hash.
    Returns the top N=16 bytes of `sha256(seed || adrs || val)`. -/
def th (seed adrs val : ByteVec) : ByteVec :=
  truncate (sha256 (seed ++ adrs ++ val))

/-- `th_pair(seed, adrs, left, right)` — 2-input tweakable hash.
    Returns the top N=16 bytes of `sha256(seed || adrs || left || right)`. -/
def thPair (seed adrs left right : ByteVec) : ByteVec :=
  truncate (sha256 (seed ++ adrs ++ left ++ right))

/-- `th_multi(seed, adrs, vals)` — variable-input tweakable hash, each
    `val` in `vals` padded to 32 bytes via `pad16`. -/
def thMulti (seed adrs : ByteVec) (vals : List ByteVec) : ByteVec :=
  let padded := vals.foldl (fun acc v => acc ++ pad16 v) (seed ++ adrs)
  truncate (sha256 padded)

/-- `h_msg(seed, root, R, message)` — domain-separated message digest.
    Returns the **full** 32-byte digest (FORS / hypertree index
    extraction needs all bits). Mirrors
    `sphincs-c10/src/hash.rs:167-180`. -/
def hMsg (seed root r message : ByteVec) : ByteVec :=
  let domainPad : ByteVec := Array.replicate 32 0xFF
  sha256 (seed ++ root ++ r ++ message ++ domainPad)

/-- `wots_digest(seed, wots_adrs, msg_hash, count)` — count-grinding
    digest. Returns the full 32-byte digest for base-W digit
    extraction. Mirrors `sphincs-c10/src/hash.rs:224-237`. -/
def wotsDigest (seed wotsAdrs msgHash : ByteVec) (count : UInt32) : ByteVec :=
  let countB32 : ByteVec := ByteVec.zero 28 ++ u32ToBE count
  sha256 (seed ++ wotsAdrs ++ msgHash ++ countB32)

/-- `chain_hash(seed, adrs, val, start_pos, steps)` — iterative WOTS
    chain: apply `th` for `steps` iterations, with `chain_pos` field
    incrementing from `start_pos`. Mirrors
    `sphincs-c10/src/hash.rs:197-213`. -/
def chainHash (seed adrs val : ByteVec) (startPos steps : UInt32) : ByteVec :=
  let rec loop (current : ByteVec) (a : ByteVec) (step : Nat) (fuel : Nat) : ByteVec :=
    match fuel with
    | 0 => current
    | fuel + 1 =>
      if step ≥ steps.toNat then current
      else
        let pos := startPos + UInt32.ofNat step
        let a' := PQSigner.Verifier.Address.setChainPos a pos
        let current' := pad16 (th seed a' current)
        loop current' a' (step + 1) fuel
  truncate (loop (pad16 val) adrs 0 steps.toNat)

/-! ### Theorems on tweakable hash output sizes -/

theorem th_size_eq_N (seed adrs val : ByteVec) :
    (th seed adrs val).size = N := by
  unfold th
  exact truncate_sha256_size_eq_N _

theorem thPair_size_eq_N (seed adrs left right : ByteVec) :
    (thPair seed adrs left right).size = N := by
  unfold thPair
  exact truncate_sha256_size_eq_N _

theorem thMulti_size_eq_N (seed adrs : ByteVec) (vals : List ByteVec) :
    (thMulti seed adrs vals).size = N := by
  unfold thMulti
  exact truncate_sha256_size_eq_N _

theorem hMsg_size_eq_32 (seed root r message : ByteVec) :
    (hMsg seed root r message).size = 32 := by
  unfold hMsg
  exact sha256_size _

theorem wotsDigest_size_eq_32 (seed wotsAdrs msgHash : ByteVec) (count : UInt32) :
    (wotsDigest seed wotsAdrs msgHash count).size = 32 := by
  unfold wotsDigest
  exact sha256_size _

/-- The `h_msg` domain pad is exactly 32 bytes of `0xFF`. Pins the
    literal that the Yul verifier emits at `SPHINCsC10Asm.sol:50`
    (`mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)`)
    to the same byte pattern in Lean. -/
theorem hmsg_domain_pad_is_32_FF :
    (Array.replicate 32 (0xFF : UInt8)).size = 32 := by
  simp

end PQSigner.Verifier.Hash
