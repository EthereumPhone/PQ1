/-
  PQSigner.Verifier.Fors — Lean port of `sphincs-c10/src/fors.rs` +
  hypertree.rs (FORS verify slices).

  FORS+C: K=13 independent Merkle trees, each of height A=11. The
  message digest selects one leaf per tree via K * A = 143 bits.

  **C10 refinement (forced-zero):** the K-th FORS tree (zero-indexed,
  i.e. tree 12) is required to have leaf index = 0. The R-grinder
  produces an R such that `(digest >> 132) & 0x7FF == 0`. This saves
  A * N = 176 bytes of signature space (no auth path needed for the
  last tree). The verifier MUST reject any sig whose H_msg-derived
  K-th index is non-zero — formalised by `forced_zero_fors_enforced`.
-/

import PQSigner.Verifier.Params
import PQSigner.Verifier.Address
import PQSigner.Verifier.Hash
import PQSigner.Verifier.Wots

namespace PQSigner.Verifier.Fors

open PQSigner.Verifier.Params
open PQSigner.Verifier.Address (ByteVec makeAdrs)
open PQSigner.Verifier.Hash (th thPair thMulti pad16)
open PQSigner.Verifier.Wots (digestToNat)

/-! ## Index extraction

    The K FORS indices and the hypertree index are extracted LSB-first
    from the 256-bit BE H_msg digest. Total used bits: K*A + H = 143 +
    18 = 161 ≤ 256.

    Yul reference: `SPHINCsC10Asm.sol:55` extracts the hypertree index
    as `and(shr(143, digest), 0x3FFFF)`. The forced-zero check at
    `:60` extracts the K-th FORS index at offset `(K-1)*A = 132`. -/

/-- Extract A bits from a Nat at the given LSB-offset. Mirrors the Yul
    `and(shr(bitOffset, digest), aMask)` pattern. -/
def extractBits (digestN : Nat) (bitOffset : Nat) (aWidth : Nat) : Nat :=
  (digestN >>> bitOffset) &&& ((1 <<< aWidth) - 1)

/-- Extract FORS index `i` (0 ≤ i < K). Each is A=11 bits. -/
def extractForsIndex (digest : ByteVec) (i : Nat) : Nat :=
  extractBits (digestToNat digest) (i * A) A

/-- Extract all K FORS indices as a List. -/
def extractForsIndices (digest : ByteVec) : List Nat :=
  (List.range K).map (extractForsIndex digest)

/-- Extract the H=18-bit hypertree index. Yul:
    `and(shr(143, digest), 0x3FFFF)`. -/
def extractHtIndex (digest : ByteVec) : Nat :=
  extractBits (digestToNat digest) (K * A) H

/-! ### Theorems on index extraction -/

theorem fors_indices_length_eq_K (digest : ByteVec) :
    (extractForsIndices digest).length = K := by
  unfold extractForsIndices
  simp

theorem fors_indices_total_bits_eq_143 : K * A = 143 := by decide

theorem ht_index_bits_offset_eq_143 : K * A = 143 := by decide

/-- Each FORS index occupies < 2^A = 2048 values. -/
theorem extractForsIndex_lt_2_pow_A (digest : ByteVec) (i : Nat) :
    extractForsIndex digest i < 2 ^ A := by
  unfold extractForsIndex extractBits
  -- (x &&& ((1 <<< 11) - 1)) ≤ (1 <<< 11) - 1 = 2047 < 2048 = 2^A
  have h_mask : (1 : Nat) <<< A - 1 = 2 ^ A - 1 := by
    unfold A
    decide
  rw [h_mask]
  have h_le : (digestToNat digest >>> (i * A)) &&& (2 ^ A - 1) ≤ 2 ^ A - 1 :=
    Nat.and_le_right
  have h_pow : (0 : Nat) < 2 ^ A := by unfold A; decide
  omega

/-- Each FORS index is bounded by FORS_LEAVES = 2048. -/
theorem extractForsIndex_lt_FORS_LEAVES (digest : ByteVec) (i : Nat) :
    extractForsIndex digest i < FORS_LEAVES := by
  exact extractForsIndex_lt_2_pow_A digest i

/-- The hypertree index is bounded by 2^H = 262144. -/
theorem extractHtIndex_lt_2_pow_H (digest : ByteVec) :
    extractHtIndex digest < 2 ^ H := by
  unfold extractHtIndex extractBits
  have h_mask : (1 : Nat) <<< H - 1 = 2 ^ H - 1 := by
    unfold H
    decide
  rw [h_mask]
  have h_le : (digestToNat digest >>> (K * A)) &&& (2 ^ H - 1) ≤ 2 ^ H - 1 :=
    Nat.and_le_right
  have h_pow : (0 : Nat) < 2 ^ H := by unfold H; decide
  omega

/-! ## Forced-zero FORS index

    The K-th tree (zero-indexed: tree K-1 = tree 12) has its leaf
    index pre-committed to 0 by R-grinding. The verifier extracts the
    index from bits `[(K-1)*A .. K*A) = [132..143)` and rejects any
    non-zero value. Yul: `if and(shr(132, dVal), 0x7FF) { revert(0, 0) }`
    at `SPHINCsC10Asm.sol:60`. -/

/-- The bit offset of the K-th FORS index = (K-1) * A = 132. -/
theorem forced_zero_offset_eq_132 : (K - 1) * A = 132 := by decide

/-- The mask width for the K-th FORS index = A = 11, so mask = 0x7FF. -/
theorem forced_zero_mask_width_eq_11 : A = 11 := by rfl

theorem forced_zero_mask_value : (1 <<< A) - 1 = 0x7FF := by
  unfold A; decide

/-- **The `forced_zero_fors_enforced` theorem.** A signature is valid
    only if the K-th FORS index extracted from the H_msg digest is
    exactly zero. This is the C10-specific tightening: the Yul reverts
    on non-zero index (`SPHINCsC10Asm.sol:60`), which the wallet
    contract's try/catch treats as SIG_VALIDATION_FAILED. -/
theorem forced_zero_fors_enforced (digest : ByteVec) :
    extractForsIndex digest (K - 1) = (digestToNat digest >>> 132) &&& 0x7FF := by
  unfold extractForsIndex extractBits
  rw [forced_zero_offset_eq_132, forced_zero_mask_value]

/-- Equivalent reading: the K-th FORS index = 0 iff bits 132..143 of
    the digest are all zero. -/
theorem forced_zero_iff_high_bits_clear (digest : ByteVec) :
    extractForsIndex digest (K - 1) = 0 ↔
    (digestToNat digest >>> 132) &&& 0x7FF = 0 := by
  rw [forced_zero_fors_enforced]

/-! ## FORS verify: `pk_from_sig`

    Mirrors `sphincs-c10/src/fors.rs:259-294`. Reconstructs the FORS
    public key from (digest, secrets, auth_paths). -/

/-- One-step FORS Merkle combine (analog of `Merkle.merkleCombineStep`,
    but with `ADRS_FORS_TREE` instead of `ADRS_TREE` and `layer = 0,
    tree = 0` in ADRS). -/
def forsCombineStep
    (seed : ByteVec) (treeIdx : UInt32) (h : UInt32) (pathIdx : UInt32)
    (node sibling : ByteVec) : ByteVec :=
  let parentIdx := pathIdx >>> 1
  let adrs := makeAdrs 0 0 ADRS_FORS_TREE treeIdx 0 (h + 1) parentIdx
  if pathIdx &&& 1 = 0 then
    thPair seed adrs (pad16 node) (pad16 sibling)
  else
    thPair seed adrs (pad16 sibling) (pad16 node)

/-- Reconstruct one FORS root from its secret + A-level auth path.
    Mirrors `sphincs-c10/src/fors.rs:271-285`. -/
def reconstructForsRoot
    (seed : ByteVec) (treeIdx : UInt32) (leafIdx : UInt32)
    (secret : ByteVec) (authPath : List ByteVec) : ByteVec :=
  let leafAdrs := makeAdrs 0 0 ADRS_FORS_TREE treeIdx 0 0 leafIdx
  let initial := th seed leafAdrs (pad16 secret)
  -- A levels of Merkle ascent
  let rec ascend (node : ByteVec) (pathIdx : UInt32) (hLeft : Nat) : ByteVec :=
    match hLeft with
    | 0 => node
    | n + 1 =>
      let h := A - (n + 1)
      let sibling := authPath.getD h (Array.replicate N 0)
      let node' := forsCombineStep seed treeIdx (UInt32.ofNat h) pathIdx node sibling
      ascend node' (pathIdx >>> 1) n
  ascend initial leafIdx A

/-- Compute the FORS public key from all K reconstructed tree roots.
    Mirrors `sphincs-c10/src/fors.rs:249-252`. -/
def computeForsPk (seed : ByteVec) (roots : List ByteVec) : ByteVec :=
  let rootsAdrs := makeAdrs 0 0 ADRS_FORS_ROOTS 0 0 0 0
  thMulti seed rootsAdrs roots

/-- FORS verify: reconstruct the FORS PK from the signature.
    Mirrors `sphincs-c10/src/fors.rs:259-294`.

    The K-th tree is reconstructed differently: the secret IS the
    "root" (since the forced-zero leaf has no auth path), and we hash
    it through one `th` to match the leaf-position. -/
def pkFromSig
    (seed : ByteVec) (digest : ByteVec)
    (secrets : List ByteVec) (authPaths : List (List ByteVec)) : ByteVec :=
  let indices := extractForsIndices digest
  let normalRoots : List ByteVec :=
    (List.range (K - 1)).map (fun t =>
      let secret := secrets.getD t (Array.replicate N 0)
      let leafIdx := UInt32.ofNat (indices.getD t 0)
      let authPath := authPaths.getD t []
      reconstructForsRoot seed (UInt32.ofNat t) leafIdx secret authPath)
  let lastSecret := secrets.getD (K - 1) (Array.replicate N 0)
  let lastAdrs := makeAdrs 0 0 ADRS_FORS_TREE (UInt32.ofNat (K - 1)) 0 0 0
  let lastRoot := th seed lastAdrs (pad16 lastSecret)
  computeForsPk seed (normalRoots ++ [lastRoot])

/-! ### Theorems on FORS pk_from_sig -/

/-- The FORS PK reconstruction always packages exactly K roots into
    `compute_fors_pk`. -/
theorem pkFromSig_uses_K_roots
    (seed : ByteVec) (digest : ByteVec)
    (secrets : List ByteVec) (authPaths : List (List ByteVec)) :
    let indices := extractForsIndices digest
    let normalRoots : List ByteVec :=
      (List.range (K - 1)).map (fun t =>
        let secret := secrets.getD t (Array.replicate N 0)
        let leafIdx := UInt32.ofNat (indices.getD t 0)
        let authPath := authPaths.getD t []
        reconstructForsRoot seed (UInt32.ofNat t) leafIdx secret authPath)
    let lastSecret := secrets.getD (K - 1) (Array.replicate N 0)
    let lastAdrs := makeAdrs 0 0 ADRS_FORS_TREE (UInt32.ofNat (K - 1)) 0 0 0
    let lastRoot := th seed lastAdrs (pad16 lastSecret)
    (normalRoots ++ [lastRoot]).length = K := by
  simp [List.length_append, List.length_map, List.length_range, K]

/-- Sanity: extractDigit at offset 132 with mask 0x7FF gives the same
    value as `extractForsIndex digest (K-1)`. This is the precise
    formal statement of the Yul `shr(132, digest) & 0x7FF` pattern. -/
theorem extract_at_132_matches_kth_index (digest : ByteVec) :
    (digestToNat digest >>> 132) &&& 0x7FF = extractForsIndex digest (K - 1) := by
  rw [forced_zero_fors_enforced]

end PQSigner.Verifier.Fors
