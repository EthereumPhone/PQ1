/- Universal WOTS digest/digit correspondence to the source-checked verifier.
   The SHA implementation remains an explicitly supplied backend boundary. -/
import Extracted.HashSpecs.WotsDigest
import Extracted.WotsDigits
import Extracted.ForsSpecBridge
import Extracted.WotsSpecVendored

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

set_option maxRecDepth 8192 in
/-- Every 32-bit wire counter is covered, including values outside the
    signer's search range. The digest is the full 32-byte result. -/
theorem firmware_wots_digest_matches_vendored
    (seed adrs message : Std.Array Std.U8 32#usize) (count : Std.U32) :
    sphincs_c10.hash.wots_digest seed adrs message count
      ⦃ d => toSpecDigest d = wotsDigest (toSpecDigest seed) (toSpecDigest adrs)
        (toSpecDigest message) (UInt32.ofNat count.val) ⦄ := by
  apply WP.spec_mono (sphincs_c10.hash.wots_digest_spec seed adrs message count)
  intro d hd
  subst d
  apply (show ∀ a b : ByteVec 32, a.data = b.data → a = b from
    fun ⟨a, _⟩ ⟨b, _⟩ h => by cases h; rfl)
  rw [wots_digest_pure_def, sha256_toSpec]
  unfold wotsDigest
  rw [sha256_eq_impl]
  unfold sha256_impl ByteSeg.flatten ByteSeg.ofByteVec
  apply congrArg Sha256Impl.sha256Bytes
  have hc : count.val < 4294967296 := count.hBounds
  simp [Sha256Pure.toUInt8Array, toSpecDigest, ByteVec.u32ToB32,
    ByteVec.cast, ByteVec.append, ByteVec.zero, ByteVec.ofU32BE, u32beBytes,
    Nat.mod_eq_of_lt hc,
    List.map_append, List.append_assoc]
  have byte (n : Nat) : UInt8.ofNat (n % 256) = UInt8.ofNat n &&& 255 := by
    apply UInt8.toNat_inj.mp
    change (n % 256) % 256 = (n % 256) &&& 255
    rw [show (255 : Nat) = 2^8 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
  exact ⟨byte _, byte _, byte _, byte _⟩

/-- All 43 digits agree with the verifier's independent bit loop, for
    every digest; no accepted-sum or hash-distribution premise. -/
theorem firmware_extract_digits_matches_vendored (digest : Std.Array Std.U8 32#usize) :
    sphincs_c10.wots.extract_digits digest
      ⦃ r => ∀ j, j < 43 → (r.val[j]!).val =
        (SphincsCVerify.Util.extractDigits (toSpecDigest digest)).getD j 0 ⦄ := by
  let* ⟨digits, hi⟩ ← extract_digits_spec digest
  rename_i j hj
  unfold SphincsCVerify.Util.extractDigits
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
    dif_pos (show j < L from hj), Option.getD_some,
    vendored_readBitsLe_eq_digestWord digest _ _ (by simp only [LogW]; omega)]
  exact hi j hj

/-- The complete array agrees, including its length and digit order. -/
theorem firmware_wots_digit_array_matches_vendored (digest : Std.Array Std.U8 32#usize) :
    sphincs_c10.wots.extract_digits digest
      ⦃ r => (r.val.map (·.val)).toArray =
        SphincsCVerify.Util.extractDigits (toSpecDigest digest) ⦄ := by
  let* ⟨digits, hi⟩ ← firmware_extract_digits_matches_vendored digest
  have hlen : digits.val.length = 43 := by simpa using digits.property
  apply Array.ext
  · simp [hlen, SphincsCVerify.Util.extractDigits, L]
  intro i hi1 hi2
  have hlt : i < 43 := by simpa [hlen] using hi1
  have h := hi i hlt
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem hi2, Option.getD_some] at h
  simpa only [List.getElem_toArray, List.getElem_map,
    getElem!_pos digits.val i (by omega)] using h

/-- Summing the actual extracted digits gives the verifier's digitSum.
    This is a component result, not a proof of the grinder or verifier caller. -/
theorem firmware_wots_digit_sum_matches_vendored (digest : Std.Array Std.U8 32#usize) :
    sphincs_c10.wots.extract_digits digest
      ⦃ r => (r.val.map (·.val)).sum =
        SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits (toSpecDigest digest)) ⦄ := by
  let* ⟨digits, hi⟩ ← firmware_wots_digit_array_matches_vendored digest
  rw [← hi]
  simp [SphincsCVerify.Util.digitSum, List.sum_eq_foldl]

end Extracted.Equiv
