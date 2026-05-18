/-
Lean model of `PQSmartWallet._erc1271IsValidSignatureNowCalldata`.

The EIP-1271 path is the **view-only** signature-validation entry point
used by Solady's `ERC1271` base for off-chain signature checking. It is
exactly the validateUserOp signature check minus the counter bumps:

  * Decode `SignatureWrapper(ownerIndex, signatureData)`.
  * Reject if `ownerIndex == 0` (bootstrap key is reserved for on-chain
    slot registration; off-chain sigs MUST use a slot key).
  * Look up `ownerAtIndex[ownerIndex]`, extract `(pkSeed, pkRoot)`.
  * Verify the inner C10 sig via `c10Verifier.verify`.

The corresponding wallet invariant (I-6) is
`erc1271IsValidSignature_rejects_bootstrap`: the function returns
`false` whenever the wrapped owner index is zero.

Mirrors `PQSmartWallet.sol` lines 401-443.
-/

import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable

namespace SphincsCVerify.Wallet.IsValidSignature

open SphincsCVerify.Spec
open SphincsCVerify.Wallet
open SphincsCVerify.Wallet.Storage
open SphincsCVerify.Wallet.ValidateUserOp

/-- The wallet's EIP-1271 entry point as a pure Lean function. -/
def erc1271IsValidSignature
    (s : Storage)
    (hash : ByteVec 32)
    (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool) :
    Bool :=
  match decodeWrappedSig signature with
  | none => false
  | some ⟨ownerIndex, innerSig⟩ =>
    if ownerIndex = 0 then
      false  -- bootstrap key forbidden for off-chain sigs.
    else
      match s.ownerAtIndex ownerIndex with
      | none => false
      | some owner =>
        let pkSeed : ByteVec 32 := owner.raw.take 32 (by decide)
        let pkRoot : ByteVec 32 := owner.raw.drop 32 (by decide)
        verify_fn pkSeed pkRoot hash innerSig

/-- **I-6: EIP-1271 rejects bootstrap.** Whenever the wrapped owner
    index is zero, the function returns `false`. -/
theorem erc1271IsValidSignature_rejects_bootstrap
    (s : Storage) (hash : ByteVec 32) (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig)
    (hdec : decodeWrappedSig signature = some d)
    (h0 : d.ownerIndex = 0) :
    erc1271IsValidSignature s hash signature verify_fn = false := by
  unfold erc1271IsValidSignature
  rw [hdec]
  obtain ⟨oi, isig⟩ := d
  simp at h0
  subst h0
  simp

/-- Corollary: the function never returns `true` on a bootstrap-wrapped
    signature, regardless of inner verifier acceptance. -/
theorem erc1271_bootstrap_never_succeeds
    (s : Storage) (hash : ByteVec 32) (signature : Array UInt8)
    (verify_fn : ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool)
    (d : DecodedSig)
    (hdec : decodeWrappedSig signature = some d)
    (h0 : d.ownerIndex = 0) :
    erc1271IsValidSignature s hash signature verify_fn ≠ true := by
  have := erc1271IsValidSignature_rejects_bootstrap s hash signature verify_fn d hdec h0
  rw [this]
  decide

end SphincsCVerify.Wallet.IsValidSignature
