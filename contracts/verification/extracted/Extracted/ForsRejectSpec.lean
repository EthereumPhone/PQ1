/- The actual verifier rejects a nonzero forced-zero FORS index before parsing
   the forest or WOTS bodies. The existing SHA backend is explicit. -/
import Extracted.ForsForestSpec
open Aeneas Aeneas.Std Result ControlFlow
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 4000000
set_option maxRecDepth 8192

def verifierRandomizer (sig : Std.Array Std.U8 4008#usize) : Std.Array Std.U8 16#usize :=
  ⟨sig.val.take 16, by have h := sig.property; simp_all⟩

def verifierDigest (seed root : Std.Array Std.U8 16#usize)
    (message : Std.Array Std.U8 32#usize) (sig : Std.Array Std.U8 4008#usize) :
    Std.Array Std.U8 32#usize :=
  sha256_pure ((pad16Pure seed).val ++ (pad16Pure root).val ++
    (pad16Pure (verifierRandomizer sig)).val ++ message.val ++ List.replicate 32 255#u8)

/-- Refusal is proved on the whole actual verifier, for every represented
    signature whose digest's final FORS field is nonzero. -/
theorem firmware_verify_rejects_nonzero_fors (seed root : Std.Array Std.U8 16#usize)
    (message : Std.Array Std.U8 32#usize) (sig : Std.Array Std.U8 4008#usize)
    (hbad : (digestWord (verifierDigest seed root message sig) >>> 132) % 2^11 ≠ 0) :
    hypertree.verify seed root message sig ⦃ r => r = false ⦄ := by
  unfold hypertree.verify
  let* ⟨s, hs⟩ ← pad16_pure_spec seed
  let* ⟨r, hr⟩ ← pad16_pure_spec root
  step
  step
  step
  · have hlen := sig.property
    simp_all [params.N, Slice.length, Array.val_to_slice]
  step
  · simp only [s1_post2, i_post, params.N, Nat.zero_add, Nat.sub_zero, Slice.length,
      s_post1, Array.repeat_val, List.length_replicate]
  have hrandom : to_slice_mut_back s2 = verifierRandomizer sig := by
    apply Subtype.ext
    simp only [s_post2, s2_post]
    rw [Array.from_slice_val _ _ (by simpa only [Slice.length, i_post, params.N,
      Nat.zero_add, Nat.sub_zero] using s1_post2)]
    simp only [s1_post1, i_post, params.N, Array.val_to_slice, verifierRandomizer,
      List.slice, Nat.zero_add, Nat.sub_zero, List.drop_zero]
    rfl
  rw [hrandom]
  let* ⟨rb, hrb⟩ ← pad16_pure_spec (verifierRandomizer sig)
  rw [hs, hr, hrb, hash.h_msg_spec]
  simp only [bind_tc_ok]
  rw [← verifierDigest]
  let* ⟨indices, hi⟩ ← extract_fors_indices_spec (verifierDigest seed root message sig)
  let* ⟨ht, hht⟩ ← extract_ht_index_spec (verifierDigest seed root message sig)
  step
  · simp [params.K]
  have hi1 : i1.val = 12 := by simpa only [params.K] using i1_post1
  step
  have hn : i2.val ≠ 0 := by
    rw [i2_post, ← getElem!_pos indices.val i1.val (by
      have h := indices.property; simp_all), hi1, hi 12 (by decide)]
    exact hbad
  have hne : i2 ≠ 0#u32 := by
    intro h
    exact hn (congrArg UScalar.val h)
  have hb : (i2 != 0#u32) = true := by simpa using hne
  simp only [hb, if_true, WP.spec_ok]
end Extracted.Equiv
