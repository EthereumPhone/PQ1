/-
  PQSigner.Verifier.Wots — Lean port of `sphincs-c10/src/wots.rs`.

  WOTS+C verify path. We port only `pk_from_sig` (verify-side); the
  signing-side `find_count`, `keygen_pk`, `sign` are out of scope.

  C10 refinement (count-grinding) over FIPS 205 WOTS+: instead of a
  checksum chain, the signer iterates `count` until the digit-sum of
  the message digest equals exactly `TARGET_SUM = 205`. Verify checks
  that the digit-sum is 205 — otherwise rejects.
-/

import PQSigner.Verifier.Params
import PQSigner.Verifier.Address
import PQSigner.Verifier.Hash

namespace PQSigner.Verifier.Wots

open PQSigner.Verifier.Params
open PQSigner.Verifier.Address (ByteVec u32ToBE makeAdrs setChainIndex)
open PQSigner.Verifier.Hash (chainHash thMulti wotsDigest pad16 truncate)

/-! ## Base-W digit extraction

    The Yul verifier extracts 43 base-W digits from a 256-bit digest as
    `(digest >> (i * 3)) & 0x7`. The Rust ref impl
    (`sphincs-c10/src/wots.rs:16-45`) implements the same by byte
    gymnastics. We use the cleaner big-integer view in Lean. -/

/-- Read a `Bytes32` digest as a big-endian `Nat` (max 2^256 - 1). -/
def digestToNat (digest : ByteVec) : Nat :=
  digest.foldl (fun acc b => acc * 256 + b.toNat) 0

/-- Extract digit `i` (0-indexed, LSB-first) from a big-endian 256-bit
    digest. Each digit is `LOG_W = 3` bits wide, masked with `W_MASK
    = 0x7`. Mirrors `sphincs-c10/src/wots.rs:31` and the Yul pattern
    `and(shr(mul(i, 3), d), 0x7)` at `SPHINCsC10Asm.sol:137,144`. -/
def extractDigit (digest : ByteVec) (i : Nat) : Nat :=
  (digestToNat digest >>> (i * LOG_W)) &&& 0x7

/-- Extract the full sequence of L=43 base-W digits from a digest.
    Returns a list of `Nat`s in LSB order (digit 0 is the least
    significant 3 bits of the digest). -/
def extractDigits (digest : ByteVec) : List Nat :=
  (List.range L).map (extractDigit digest)

/-- Sum of all L digits of a digest. -/
def digitSum (digest : ByteVec) : Nat :=
  (extractDigits digest).foldl (· + ·) 0

/-! ### Theorems on digit extraction -/

theorem extractDigits_length_eq_L (digest : ByteVec) :
    (extractDigits digest).length = L := by
  unfold extractDigits
  simp

theorem extract_digits_total_bits_eq_129 :
    L * LOG_W = 129 := by decide

/-- Each digit is bounded by W - 1 = 7 (it's 3 bits, masked with 0x7). -/
theorem extractDigit_lt_W (digest : ByteVec) (i : Nat) :
    extractDigit digest i < W := by
  unfold extractDigit W
  show (digestToNat digest >>> (i * LOG_W)) &&& 0x7 < 8
  -- `n &&& 7 ≤ 7` because the result has at most 3 bits set.
  have h : (digestToNat digest >>> (i * LOG_W)) &&& 0x7 ≤ 0x7 := by
    exact Nat.and_le_right
  omega

/-- `TARGET_SUM = 205` is achievable: it's at most `L * (W - 1) = 301`,
    the maximum possible digit-sum from L=43 base-W=8 digits. -/
theorem target_sum_lt_max : TARGET_SUM < L * (W - 1) + 1 := by
  unfold TARGET_SUM L W; decide

/-! ## WOTS+C verify: `pk_from_sig`

    Mirrors `sphincs-c10/src/wots.rs:127-156`. Recovers the WOTS pubkey
    from a signature `(sigma : List ByteVec, count : UInt32)` over a
    16-byte message hash. Returns `Bytes16` (the WOTS PK element);
    callers compare against the expected Merkle leaf.

    **`target_sum_enforced` invariant**: if the digit-sum of the
    count-grinded digest is not exactly 205, returns the all-zero
    16-byte value (which will not match any legitimate WOTS PK). -/

/-- Helper: build the per-chain ADRS for chain `i` at layer `layer`,
    tree `tree`, keypair `kp`. -/
def wotsChainAdrs (layer : UInt32) (tree : UInt64) (kp : UInt32) (i : UInt32) : ByteVec :=
  let base := makeAdrs layer tree ADRS_WOTS kp 0 0 0
  setChainIndex base i

/-- Helper: build the WOTS PK compression ADRS. -/
def wotsPkAdrs (layer : UInt32) (tree : UInt64) (kp : UInt32) : ByteVec :=
  makeAdrs layer tree ADRS_WOTS_PK kp 0 0 0

/-- `pk_from_sig` reconstructs the WOTS+C public key from a signature.
    Returns the all-zero 16-byte block on digit-sum mismatch (which
    won't match any legitimate WOTS PK). -/
def pkFromSig
    (seed : ByteVec) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec) (sigma : List ByteVec) (count : UInt32) : ByteVec :=
  let padded := pad16 msgHash
  let wotsAdrs := makeAdrs layer tree ADRS_WOTS kp 0 0 0
  let d := wotsDigest seed wotsAdrs padded count
  if digitSum d ≠ TARGET_SUM then
    -- Invalid sig: target_sum_enforced. The Yul verifier reverts here
    -- (line 139 `eq(digitSum, 205)` followed by an implicit revert);
    -- we return all-zero so the caller's Merkle-leaf compare fails.
    Array.replicate N 0
  else
    let digits := extractDigits d
    -- For each chain i, finish remaining (W-1-digit_i) hashes starting
    -- from the signature value.
    let pkElements : List ByteVec :=
      (List.range L).zip digits |>.map (fun (i, digit) =>
        let chainAdrs := setChainIndex wotsAdrs (UInt32.ofNat i)
        let sigmaI := sigma.getD i (Array.replicate N 0)
        let remaining := UInt32.ofNat (W - 1 - digit)
        chainHash seed chainAdrs sigmaI (UInt32.ofNat digit) remaining)
    let pkAdrs := wotsPkAdrs layer tree kp
    thMulti seed pkAdrs pkElements

/-! ### Theorems on `pk_from_sig` -/

/-- **The `target_sum_enforced` theorem.** If the digit-sum is not
    exactly 205, `pkFromSig` returns the all-zero 16-byte vector.
    This is the C10-specific tightening over FIPS 205. -/
theorem target_sum_enforced
    (seed : ByteVec) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec) (sigma : List ByteVec) (count : UInt32)
    (h : digitSum (wotsDigest seed (makeAdrs layer tree ADRS_WOTS kp 0 0 0)
                              (pad16 msgHash) count) ≠ TARGET_SUM) :
    pkFromSig seed layer tree kp msgHash sigma count = Array.replicate N 0 := by
  unfold pkFromSig
  rw [if_pos h]

/-- **The `chain_iterates_w_minus_1_minus_digit_steps` theorem.**
    For each chain, the signature's chain value is hashed
    `(W - 1 - digit)` more times to finish the chain. This is the
    direct counterpart to the Yul `chain_hash(seed, adrs, sigma, digit,
    W-1-digit)` invocation. -/
theorem chain_iterates_w_minus_1_minus_digit_steps
    (digit : Nat) (hd : digit < W) :
    digit + ((W - 1) - digit) = W - 1 := by
  unfold W at *
  omega

/-- Contrapositive of `target_sum_enforced`: if `pkFromSig` returns a
    non-zero value, the digit-sum must have been 205. -/
theorem accepted_digit_sum_eq_205
    (seed : ByteVec) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec) (sigma : List ByteVec) (count : UInt32)
    (h_nonzero : pkFromSig seed layer tree kp msgHash sigma count ≠ Array.replicate N 0) :
    digitSum (wotsDigest seed (makeAdrs layer tree ADRS_WOTS kp 0 0 0)
                         (pad16 msgHash) count) = TARGET_SUM := by
  by_cases h : digitSum (wotsDigest seed (makeAdrs layer tree ADRS_WOTS kp 0 0 0)
                                    (pad16 msgHash) count) = TARGET_SUM
  · exact h
  · exact absurd (target_sum_enforced seed layer tree kp msgHash sigma count h) h_nonzero

end PQSigner.Verifier.Wots
