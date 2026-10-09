/- Secret preimage correspondence to the faithful verifier declaration. -/
import Extracted.WotsSecretSpec
import Extracted.WotsKeygenVendored
import Extracted.WotsRecoveryBridge

open Aeneas Aeneas.Std Result
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

private theorem byteVec_ext {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; cases h; rfl

theorem secret_tree_bytes (tree : Std.U64) :
    ((wotsTreeBytes tree).map (fun b => UInt8.ofNat b.val)).toArray =
      (ByteVec.u64ToB32 (UInt64.ofNat tree.val)).data := by
  have ht : (UInt64.ofNat tree.val).toNat = tree.val := by
    change tree.val % 2^64 = tree.val
    exact Nat.mod_eq_of_lt tree.hBounds
  have byte (m : Nat) : UInt8.ofNat (m % 256) = UInt8.ofNat (m &&& 255) := by
    rw [show (255 : Nat) = 2^8-1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
  have hm : (tree.bv.toBEBytes.map (@UScalar.mk .U8)).map (fun b => UInt8.ofNat b.val) =
      (u64be tree.val).map UInt8.ofNat := by
    rw [List.map_map]
    change tree.bv.toBEBytes.map (UInt8.ofNat ∘ BitVec.toNat) = _
    rw [← List.map_map, toBEBytes64_map_toNat]
    rfl
  simp only [wotsTreeBytes, List.map_append, List.map_replicate, hm,
    ByteVec.u64ToB32, ByteVec.cast, ByteVec.append,
    ByteVec.zero, ByteVec.ofU64BE, ht]
  simp [u64be, Nat.shiftRight_eq_div_pow, ← byte]
  apply UInt8.toNat_inj.mp
  simp

theorem wots_secret_pure_matches_vendored (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) :
    toSpecNode (wotsSecretPure sk layer tree kp chain) =
      wotsSecret (toSpecDigest sk) (UInt32.ofNat layer.val) (UInt64.ofNat tree.val)
        (UInt32.ofNat kp.val) (UInt32.ofNat chain.val) := by
  rw [wotsSecretPure, recovery_truncate]
  unfold wotsSecret
  congr 1
  apply byteVec_ext
  rw [recovery_sha, sha256_eq_impl]
  unfold sha256_impl
  apply congrArg Sha256Impl.sha256Bytes
  have hu32 (x : Std.U32) :
      (u32beBytes x.val).map (fun b => UInt8.ofNat b.val) =
        (ByteVec.ofU32BE (UInt32.ofNat x.val)).data.toList := by
    simpa using congrArg _root_.Array.toList (recovery_u32be x.val x.hBounds)
  have htree : (wotsTreeBytes tree).map (fun b => UInt8.ofNat b.val) =
      (ByteVec.u64ToB32 (UInt64.ofNat tree.val)).data.toList := by
    simpa using congrArg _root_.Array.toList (secret_tree_bytes tree)
  simp [Sha256Pure.toUInt8Array, wotsSecretPreimage, ByteSeg.flatten,
    ByteSeg.ofByteVec, toSpecDigest, ByteVec.wotsTag, Array.append_assoc, hu32, htree]

/-- Actual extracted secret derivation agrees at every address and secret seed. -/
theorem firmware_wots_secret_matches_vendored (sk : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp chain : Std.U32) :
    sphincs_c10.hash.wots_secret sk layer tree kp chain ⦃ r =>
      toSpecNode r = wotsSecret (toSpecDigest sk) (UInt32.ofNat layer.val)
        (UInt64.ofNat tree.val) (UInt32.ofNat kp.val) (UInt32.ofNat chain.val) ⦄ := by
  let* ⟨r, hr⟩ ← wots_secret_spec sk layer tree kp chain
  rw [hr]
  exact wots_secret_pure_matches_vendored sk layer tree kp chain

end Extracted.Equiv
