/- Actual FORS secret preimage correspondence, including hypertree position. -/
import Extracted.ForsSecretSpec
import Extracted.ForsSecretVendored
import Extracted.WotsRecoveryBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

private theorem byteVec_ext {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

theorem fors_secret_pure_matches_vendored (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    toSpecNode (forsSecretPure sk ht tree leaf) =
      forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
        (UInt32.ofNat tree.val) (UInt32.ofNat leaf.val) := by
  rw [forsSecretPure, recovery_truncate]
  unfold forsSecret
  congr 1
  apply byteVec_ext
  rw [recovery_sha, sha256_eq_impl]
  unfold sha256_impl
  apply congrArg Sha256Impl.sha256Bytes
  have hu32 (x : Std.U32) :
      (u32beBytes x.val).map (fun b => UInt8.ofNat b.val) =
        (ByteVec.ofU32BE (UInt32.ofNat x.val)).data.toList := by
    simpa using congrArg _root_.Array.toList (recovery_u32be x.val x.hBounds)
  simp [Sha256Pure.toUInt8Array, forsSecretPreimage, ByteSeg.flatten,
    ByteSeg.ofByteVec, toSpecDigest, ByteVec.forsTag, Array.append_assoc, hu32]

/-- Actual secret derivation agrees for every seed and all full-width fields. -/
theorem firmware_fors_secret_matches_vendored (sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    sphincs_c10.hash.fors_secret sk ht tree leaf ⦃ r =>
      toSpecNode r = forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
        (UInt32.ofNat tree.val) (UInt32.ofNat leaf.val) ⦄ := by
  let* ⟨r, hr⟩ ← fors_secret_spec sk ht tree leaf
  rw [hr]
  exact fors_secret_pure_matches_vendored sk ht tree leaf

end Extracted.Equiv
