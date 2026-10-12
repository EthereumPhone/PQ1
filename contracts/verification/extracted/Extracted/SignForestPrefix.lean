/- Unconditional substitution of the proved forest in the actual signer.
   Grinding and the unchanged suffix retain failure/divergence behavior. -/
import Extracted.SignForestBridge
open Aeneas Aeneas.Std Result ControlFlow Error
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192

def signerAfterCanonicalForest (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : Std.Array Std.U8 4008#usize)
    (indices : Std.Array Std.U32 13#usize) (ht : Std.U32)
    (offset last : Std.Usize) (left : Std.U32) : Result (Std.Array Std.U8 4008#usize) := do
  if left = 0#u32 then
    hypertree.report progress 5#u8
    signerAfterForest sk seed root progress shuffle sig ht offset last
      (forsSignerRoots seed sk ht) (forsSignerSecrets seed sk ht indices)
      (forsSignerPaths seed sk ht indices)
  else
    let _ ← core.fmt.Arguments.from_str (toStr "Last FORS index must be 0 after R-grinding" (by (conv_lhs => rw [← String.ofList_toList (s := "Last FORS index must be 0 after R-grinding"), String.toByteArray_ofList]); simp only [List.utf8Encode, List.size_toByteArray]; simp [String.utf8EncodeChar]; scalar_tac))
    fail panic

theorem signer_after_head_canonical (sk seed : Std.Array Std.U8 32#usize)
    (root : Std.Array Std.U8 16#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) (sig : Std.Array Std.U8 4008#usize)
    (indices : Std.Array Std.U32 13#usize) (ht : Std.U32) (offset : Std.Usize) (left : Std.U32)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    signerAfterHead sk seed root progress shuffle sig indices ht offset 12#usize left =
      signerAfterCanonicalForest sk seed root progress shuffle sig indices ht offset 12#usize left := by
  obtain ⟨signed, hrun, hsigned⟩ := WP.spec_imp_exists
    (signer_fors_phase_spec seed sk ht indices progress shuffle hi)
  rw [hsigned] at hrun
  unfold signerAfterHead signerAfterCanonicalForest
  split <;> simp only [hypertree.report, bind_tc_ok, hrun] <;> rfl

/-- For every signer input, replace precisely its forest construction with the
    proved canonical values. No successful grinding or signer output is assumed. -/
theorem firmware_sign_fors_prefix (sk : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (msg : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.sign_inner sk seed root msg opt progress shuffle = (do
      let (s, sig, indices, ht, offset, last, left) ← signerHead sk seed root msg opt progress
      signerAfterCanonicalForest sk s root progress shuffle sig indices ht offset last left) := by
  rw [signer_forest_factor]
  simp only [signerHead, bind_assoc_eq]
  rw [bind_eq_iff]
  intro s hs
  rw [bind_eq_iff]
  intro u hu
  rw [bind_eq_iff]
  intro rg hrg
  rcases rg with ⟨r, digest⟩
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]
  rw [bind_eq_iff]
  intro i hi
  rw [bind_eq_iff]
  intro pair hp
  rcases pair with ⟨slice, back⟩
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]
  rw [bind_eq_iff]
  intro s1 hs1
  rw [bind_eq_iff]
  intro s2 hs2
  rw [bind_eq_iff]
  intro indices hindices
  rw [bind_eq_iff]
  intro ht hht
  rw [bind_eq_iff]
  intro last hlast
  rw [bind_eq_iff]
  intro left hleft
  obtain ⟨decoded, hd, hv⟩ := WP.spec_imp_exists (extract_fors_indices_spec digest)
  rw [hindices] at hd
  have he : indices = decoded := Result.ok.inj hd
  have hbound : ∀ j, j < 12 → (indices.val[j]!).val < 2048 := by
    intro j hj
    rw [he, hv j (by omega)]
    exact Nat.mod_lt _ (by decide)
  obtain ⟨n, hn, hnv, _⟩ := WP.spec_imp_exists
    (Std.Usize.sub_spec (x := 13#usize) (y := 1#usize) (by scalar_tac))
  have hn12 : n = 12#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  subst n
  rw [params.K] at hlast
  rw [hn] at hlast
  have he12 : 12#usize = last := Result.ok.inj hlast
  subst last
  exact signer_after_head_canonical sk s root progress shuffle (back s2) indices ht i left hbound

end
end Extracted.Equiv
