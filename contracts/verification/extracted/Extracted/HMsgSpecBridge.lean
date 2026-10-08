/- H_msg correspondence with the verifier's source-checked specification.
   The supplied SHA backend is shared; its implementation equivalence is open. -/
import Extracted.HashSpecs.HMsg
import Extracted.HMsgSpecVendored
import Extracted.ForsSpecBridge

open Aeneas Aeneas.Std Result

attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open SphincsCVerify.Spec

private theorem sha256_toSpec (data : List Std.U8) :
    (toSpecDigest (sha256_pure data)).data =
      Sha256Impl.sha256Bytes (Sha256Pure.toUInt8Array data) := by
  have roundtrip (bytes : Array UInt8) :
      (bytes.toList.map Sha256Pure.ofUInt8 |>.map (fun b => UInt8.ofNat b.val)).toArray = bytes := by
    rw [List.map_map]
    have h : (fun b : UInt8 => UInt8.ofNat (Sha256Pure.ofUInt8 b).val) = id := by
      funext b
      simp [Sha256Pure.ofUInt8, UScalar.val]
    simp only [Function.comp_def]
    rw [h]
    simp
  change ((sha256_pure data).val.map (fun b => UInt8.ofNat b.val)).toArray = _
  rw [sha256_pure_val]
  exact roundtrip _

/-- For every seed, root, R and message, the extracted caller returns the
    verifier's full H_msg digest after the byte conversion. -/
theorem firmware_h_msg_matches_vendored
    (seed root r message : Std.Array Std.U8 32#usize) :
    sphincs_c10.hash.h_msg seed root r message
      ⦃ d => toSpecDigest d = hMsg (toSpecDigest seed) (toSpecDigest root)
        (toSpecDigest r) (toSpecDigest message) ⦄ := by
  rw [sphincs_c10.hash.h_msg_spec]
  simp only [WP.spec_ok]
  apply (show ∀ a b : ByteVec 32, a.data = b.data → a = b from
    fun ⟨a, _⟩ ⟨b, _⟩ h => by cases h; rfl)
  rw [sha256_toSpec]
  unfold hMsg
  rw [sha256_eq_impl]
  unfold sha256_impl ByteSeg.flatten ByteSeg.ofByteVec
  apply congrArg Sha256Impl.sha256Bytes
  simp [Sha256Pure.toUInt8Array, toSpecDigest, ByteVec.ones,
    List.map_append, List.append_assoc]

end Extracted.Equiv
