/-
  PQSigner.Verifier.Params — Lean port of `sphincs-c10/src/params.rs`.

  Phase 1 of `docs/handoff-verity-c10-verifier.md`. Pure-Lean
  (Lean stdlib only); no Verity dependency. Constants and the
  decomposition theorem for `SIGNATURE_LEN` so any future regression
  on the byte layout fails `lake build`.

  Mirrors `sphincs-c10/src/params.rs` line-for-line. The compile-time
  asserts in the Rust file (`assert!(SIGNATURE_LEN == 4008)` etc.)
  become Lean theorems below.
-/

namespace PQSigner.Verifier.Params

/-! ## Hash and tree parameters -/

/-- Security parameter: `n = 128` bits = 16 bytes. Mirrors
    `sphincs-c10/src/params.rs:19`. All 16-byte values are stored
    top-128-bits in a 32-byte word for EVM uint256 compatibility. -/
def N : Nat := 16

/-- Total hypertree height. `sphincs-c10/src/params.rs:22`. -/
def H : Nat := 18

/-- Number of hypertree layers. `sphincs-c10/src/params.rs:25`. -/
def D : Nat := 2

/-- Height of each subtree = `H / D`. `sphincs-c10/src/params.rs:28`. -/
def SUBTREE_H : Nat := H / D

/-- Number of leaves in each subtree = `2 ^ SUBTREE_H`. -/
def SUBTREE_LEAVES : Nat := 2 ^ SUBTREE_H

/-! ## FORS parameters -/

/-- Number of FORS trees. `sphincs-c10/src/params.rs:34`. -/
def K : Nat := 13

/-- Height of each FORS tree. `sphincs-c10/src/params.rs:37`. -/
def A : Nat := 11

/-- Number of leaves in each FORS tree = `2 ^ A`. -/
def FORS_LEAVES : Nat := 2 ^ A

/-! ## WOTS+ parameters -/

/-- Winternitz parameter. `sphincs-c10/src/params.rs:43`. -/
def W : Nat := 8

/-- log₂(W). `sphincs-c10/src/params.rs:46`. -/
def LOG_W : Nat := 3

/-- WOTS chain count. `sphincs-c10/src/params.rs:49`. -/
def L : Nat := 43

/-- WOTS+C target digit-sum for count-grinding (the C10 refinement
    over FIPS 205 — the last "checksum" digit is folded into the data
    digits via this acceptance criterion). `sphincs-c10/src/params.rs:52`. -/
def TARGET_SUM : Nat := 205

/-- Bit-mask for a single base-`W` digit = `W - 1`. -/
def W_MASK : UInt8 := UInt8.ofNat (W - 1)

/-! ## Signature layout -/

/-- R (randomizer): N bytes. -/
def SIG_R : Nat := N

/-- FORS secrets: K * N bytes. -/
def SIG_FORS_SECRETS : Nat := K * N

/-- FORS auth paths: (K-1) * A * N bytes. The K-th tree is forced-zero
    and emits only its secret as the root, no auth path follows. -/
def SIG_FORS_AUTH : Nat := (K - 1) * A * N

/-- Total FORS section: R + secrets + auth paths = 2336. -/
def SIG_FORS_TOTAL : Nat := SIG_R + SIG_FORS_SECRETS + SIG_FORS_AUTH

/-- One hypertree layer: L chain values + 4-byte count + SUBTREE_H
    auth nodes = 836. -/
def SIG_HT_LAYER : Nat := L * N + 4 + SUBTREE_H * N

/-- Total signature size = 4008. -/
def SIGNATURE_LEN : Nat := SIG_FORS_TOTAL + D * SIG_HT_LAYER

/-- Verifying key length: pkSeed(16) + pkRoot(16) = 32. -/
def VERIFYING_KEY_LEN : Nat := N + N

/-! ## ADRS type constants

    Match the Solidity verifier's bit-field values at
    `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol:67,97,106,163,173`. -/

def ADRS_WOTS : UInt32 := 0
def ADRS_WOTS_PK : UInt32 := 1
def ADRS_TREE : UInt32 := 2
def ADRS_FORS_TREE : UInt32 := 3
def ADRS_FORS_ROOTS : UInt32 := 4

/-! ## Compile-time invariants

    Mirror of the `const _: () = assert!(...)` block at
    `sphincs-c10/src/params.rs:88-91`. Any future regression to N, H,
    D, K, A, L, etc. that breaks the byte layout fails `lake build`. -/

theorem subtree_h_eq_nine : SUBTREE_H = 9 := by rfl

theorem subtree_h_times_d_eq_h : SUBTREE_H * D = H := by rfl

theorem sig_fors_total_eq_2336 : SIG_FORS_TOTAL = 2336 := by rfl

theorem sig_ht_layer_eq_836 : SIG_HT_LAYER = 836 := by rfl

theorem signature_len_eq_4008 : SIGNATURE_LEN = 4008 := by rfl

/-- Explicit decomposition of the signature into its parts. Whatever
    we change above, `SIGNATURE_LEN` must keep this shape — fails
    `lake build` otherwise. -/
theorem sig_len_decomposes :
    SIGNATURE_LEN = N + K * N + (K - 1) * A * N + D * (L * N + 4 + SUBTREE_H * N) := by
  rfl

/-- The five ADRS types are pairwise distinct. -/
theorem adrs_types_distinct :
    ADRS_WOTS ≠ ADRS_WOTS_PK ∧
    ADRS_WOTS ≠ ADRS_TREE ∧
    ADRS_WOTS ≠ ADRS_FORS_TREE ∧
    ADRS_WOTS ≠ ADRS_FORS_ROOTS ∧
    ADRS_WOTS_PK ≠ ADRS_TREE ∧
    ADRS_WOTS_PK ≠ ADRS_FORS_TREE ∧
    ADRS_WOTS_PK ≠ ADRS_FORS_ROOTS ∧
    ADRS_TREE ≠ ADRS_FORS_TREE ∧
    ADRS_TREE ≠ ADRS_FORS_ROOTS ∧
    ADRS_FORS_TREE ≠ ADRS_FORS_ROOTS := by
  decide

/-- `K - 1` levels of FORS auth paths is well-defined (no underflow). -/
theorem k_pred_eq_twelve : K - 1 = 12 := by rfl

/-- FORS index bit width × K ≤ total digest bits (256). The 13 FORS
    indices occupy `K * A = 143` bits, the hypertree index occupies
    the next `H = 18` bits — `143 + 18 = 161 ≤ 256`. -/
theorem fors_and_ht_bits_fit_in_digest : K * A + H ≤ 256 := by decide

end PQSigner.Verifier.Params
