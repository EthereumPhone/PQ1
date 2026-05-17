/-
SPHINCS+C10 parameter set.

This file is the single source of truth for the parameter values used by:
  - the Rust signer        (`sphincs-c10/src/params.rs`)
  - the Solidity verifier  (`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`)
  - the firmware signer    (the secure-world build using `sphincs-c10`)
  - this Lean verification project (`SphincsCVerify`)

If any of the four ever drifts apart, the differential test vectors and
the byte-level equivalence theorems will fail at build time.

Parameter naming follows the SPHINCS+ v3 spec (sphincs.org/data) with the
additional `target_sum` from the SPHINCS+C proposal:

  Hülsing et al., "SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost,"
  NIST PQC2022 (https://csrc.nist.gov/csrc/media/Events/2022/...).

The instance encoded here is **non-standard** (not one of the table-2
parameter sets in the PQC2022 paper) — the (h, d, h', a, k, w, len, T)
tuple is the size-optimised C10 used by PQSigner OS. The choice is
documented in `CLAUDE.md` (§ "Non-Negotiable Invariants" #5).
-/

namespace SphincsCVerify.Spec

/-! ## Parameter constants -/

/-- Security parameter `n` (output size of the truncated hash, in bytes).
    n = 16 means 128-bit collision resistance, i.e. SPHINCS+-128s class. -/
def N : Nat := 16

/-- Total hypertree height. -/
def H : Nat := 18

/-- Number of hypertree layers. -/
def D : Nat := 2

/-- Per-subtree height: `H / D`. -/
def SubtreeH : Nat := 9

/-- Number of leaves in each subtree: `2 ^ SubtreeH`. -/
def SubtreeLeaves : Nat := 1 <<< SubtreeH  -- 512

/-- Number of FORS trees. -/
def K : Nat := 13

/-- Height of each FORS tree (a). -/
def A : Nat := 11

/-- Leaves per FORS tree: `2 ^ A`. -/
def ForsLeaves : Nat := 1 <<< A  -- 2048

/-- Winternitz parameter. -/
def W : Nat := 8

/-- `log2 W`. -/
def LogW : Nat := 3

/-- WOTS chain count (no checksum chains — WOTS+C eliminates them). -/
def L : Nat := 43

/-- WOTS+C target digit sum: a count is grinded until the base-w digits
    sum to exactly this value. Eliminates the WOTS+ checksum chains. -/
def TargetSum : Nat := 205

/-- Bit mask for a single base-w digit. -/
def WMask : Nat := W - 1  -- 7 = 0b111

/-! ## Signature layout sizes (all in bytes)

These are the offsets and sizes the Solidity `SPHINCsC10Asm.verify` uses
when indexing into the `sig` calldata; they must agree exactly with the
Rust constants. The compile-time checks at the bottom of this file are
the Lean-kernel-checked equivalent of the `const _: () = assert!(...)`
fences in `params.rs`.
-/

/-- R (randomizer): `N` bytes. -/
def SigR : Nat := N

/-- FORS secret-key values: `K * N` bytes. -/
def SigForsSecrets : Nat := K * N

/-- FORS authentication paths: `(K - 1) * A * N` bytes (last tree is
    forced-zero and contributes only its root). -/
def SigForsAuth : Nat := (K - 1) * A * N

/-- Total FORS section size in the signature. -/
def SigForsTotal : Nat := SigR + SigForsSecrets + SigForsAuth

/-- One hypertree layer footprint: L chain values + 4-byte count + auth path. -/
def SigHtLayer : Nat := L * N + 4 + SubtreeH * N

/-- Total SPHINCS+C10 signature size in bytes. -/
def SignatureLen : Nat := SigForsTotal + D * SigHtLayer

/-- Signing-key seed material: 32-byte sk_seed + 16-byte pk_seed. -/
def SigningKeySeedLen : Nat := 32 + N

/-- Verifying key length: pk_seed(16) || pk_root(16). -/
def VerifyingKeyLen : Nat := N + N

/-! ## ADRS type tags -/

/-- WOTS hash address. -/
def ADRS_WOTS : Nat := 0

/-- WOTS public-key compression. -/
def ADRS_WOTS_PK : Nat := 1

/-- XMSS subtree node. -/
def ADRS_TREE : Nat := 2

/-- FORS tree leaf / inner node. -/
def ADRS_FORS_TREE : Nat := 3

/-- FORS root compression. -/
def ADRS_FORS_ROOTS : Nat := 4

/-! ## Compile-time sanity checks (Lean-kernel decided)

These are the load-bearing equalities everything downstream depends on.
`decide` reduces the LHS and RHS to concrete numerals and uses `Nat`
decidable equality. Each line is a closed theorem with no `sorry`.
-/

theorem subtreeH_times_D_eq_H : SubtreeH * D = H := by decide
theorem sigForsTotal_eq_2336 : SigForsTotal = 2336 := by decide
theorem sigHtLayer_eq_836 : SigHtLayer = 836 := by decide
theorem signatureLen_eq_4008 : SignatureLen = 4008 := by decide
theorem wMask_eq_7 : WMask = 7 := by decide
theorem W_eq_two_pow_LogW : W = 2 ^ LogW := by decide
theorem subtreeLeaves_eq_512 : SubtreeLeaves = 512 := by decide
theorem forsLeaves_eq_2048 : ForsLeaves = 2048 := by decide
theorem verifyingKeyLen_eq_32 : VerifyingKeyLen = 32 := by decide
theorem k_minus_one_a_n_eq_2112 : (K - 1) * A * N = 2112 := by decide
theorem htLayer_breakdown : L * N + 4 + SubtreeH * N = 836 := by decide

/-- `2^H` = total hypertree positions = 262,144. This bounds the
    `htIdx` produced by `H_msg` after digest extraction. -/
def HypertreePositions : Nat := 1 <<< H

theorem hypertreePositions_eq : HypertreePositions = 262144 := by decide

/-- Production usage cap per chain (per slot, per bootstrap). 2^16; well
    inside the C10 birthday-style security margin. -/
def MaxBootstrapUses : Nat := 65536
def MaxSlotUses     : Nat := 65536

theorem maxUses_lt_positions : MaxBootstrapUses < HypertreePositions := by decide

end SphincsCVerify.Spec
