/- Total forest construction, including the distinct transmitted final value
   and final compressed slot. Linked to the caller by signer_forest_factor. -/
import Extracted.SignForestFactor
import Extracted.ForsPkSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192

def forsSignerRoots (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32) : SignForestNodes :=
  ⟨(List.range 13).map (fun j => if j < 12 then
    forsRootNode seed sk ht ⟨BitVec.ofNat 32 j⟩ 11 0
    else th_pure seed (forsRecoveryAdrs ht 12#u32 0 0)
      (pad16p (forsRootNode seed sk ht 12#u32 11 0))), by simp⟩

def forsSignerSecrets (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) : SignForestNodes :=
  ⟨(List.range 13).map (fun j => if j < 12 then
    forsSecretPure sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)
    else forsRootNode seed sk ht 12#u32 11 0), by simp⟩

def forsSignerPaths (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) : SignForestPaths :=
  ⟨(List.range 12).map (fun j =>
    forsSigningPath seed sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)), by simp⟩

attribute [local irreducible] forsRootNode forsSecretPure forsSigningPath
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

theorem sign_forest_array_ext {α : Type} [Inhabited α] {n : Std.Usize}
    (a b : Std.Array α n) (h : ∀ j, j < n.val → a.val[j]! = b.val[j]!) : a = b := by
  apply Subtype.ext
  apply List.ext_getElem
  · rw [a.property, b.property]
  intro j ha hb
  rw [← getElem!_pos a.val j ha, ← getElem!_pos b.val j hb]
  exact h j (by rwa [a.property] at ha)

private theorem derive_total (seed : shuffle.ShuffleSeed) (label : Slice Std.U8) :
    shuffle.ShuffleSeed.derive seed label ⦃ _ => True ⦄ := by
  unfold shuffle.ShuffleSeed.derive
  split <;> simp only [WP.spec_ok, True.intro]

/-- All output values are determined by the signing inputs, independently of
    shuffle scheduling. The final digest index is not read by this phase. -/
theorem signer_fors_phase_spec (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (progress : hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    signerForsPhase seed sk ht indices progress shuffle 12#usize ⦃ r =>
      r = (forsSignerRoots seed sk ht, forsSignerSecrets seed sk ht indices,
        forsSignerPaths seed sk ht indices) ⦄ := by
  unfold signerForsPhase
  simp only [lift, core.convert.num.FromU64U32.from]
  let* ⟨derived, _⟩ ← derive_total shuffle
    (Array.to_slice (Array.make 4#usize [102#u8, 111#u8, 114#u8, 115#u8]))
  let* ⟨order, ho⟩ ← shuffle_permutation_spec derived 12#usize (by decide)
  let* ⟨roots, secrets, paths, hlr, hls, hrows⟩ ← firmware_sign_fors_normal_loop
    seed sk ht indices progress order
    (Array.repeat 13#usize (Array.repeat 16#usize 0#u8))
    (Array.repeat 13#usize (Array.repeat 16#usize 0#u8))
    (Array.repeat 12#usize (Array.repeat 11#usize (Array.repeat 16#usize 0#u8))) hi ho
  have hc : UScalar.cast .U32 12#usize = 12#u32 := by
    apply UScalar.eq_of_val_eq
    simp
  rw [hc]
  let* ⟨lastRoot, hroot⟩ ← fors_compute_root_spec seed sk ht 12#u32
  unfold hypertree.set_row
  let* ⟨secrets1, hs⟩ ← Array.update_spec secrets 12#usize lastRoot (by scalar_tac)
  let* ⟨adrs, ha⟩ ← make_adrs_spec 0#u32
    (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE 12#u32 0#u32 0#u32 0#u32
  have hht : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
    BitVec.toNat_setWidth_of_le (by decide)
  have hadrs : forsRecoveryAdrs ht 12#u32 0 0 = adrs := by
    apply forsRecoveryAdrs_eq_of_map_val
    simpa only [params.ADRS_FORS_TREE, hht] using ha
  let* ⟨padded, hpad⟩ ← pad16_spec lastRoot
  let* ⟨lastSlot, hslot⟩ ← hash.th_spec seed adrs padded
  let* ⟨roots1, hr⟩ ← Array.update_spec roots 12#usize lastSlot (by scalar_tac)
  have hroots : roots1 = forsSignerRoots seed sk ht := by
    apply sign_forest_array_ext
    intro j hj
    change j < 13 at hj
    rw [hr, Array.set_val_eq]
    simp only [show (12#usize).val = 12 by simp]
    by_cases hn : j < 12
    · rw [List.set_getElem!_ne _ _ _ _ (by simp; omega)]
      have hv := (hrows j hn).1
      simpa [forsSignerRoots, hj, hn] using hv
    · have he : j = 12 := by omega
      subst j
      rw [List.set_getElem!_eq _ _ _ _ ⟨by rw [roots.property]; decide, rfl⟩]
      simp only [hslot, hpad, ← hadrs, hroot]
      simp [forsSignerRoots]
  have hsecrets : secrets1 = forsSignerSecrets seed sk ht indices := by
    apply sign_forest_array_ext
    intro j hj
    change j < 13 at hj
    rw [hs, Array.set_val_eq]
    simp only [show (12#usize).val = 12 by simp]
    by_cases hn : j < 12
    · rw [List.set_getElem!_ne _ _ _ _ (by simp; omega)]
      have hv := (hrows j hn).2.1
      simpa [forsSignerSecrets, hj, hn] using hv
    · have he : j = 12 := by omega
      subst j
      rw [List.set_getElem!_eq _ _ _ _ ⟨by rw [secrets.property]; decide, rfl⟩, hroot]
      simp [forsSignerSecrets]
  have hpaths : paths = forsSignerPaths seed sk ht indices := by
    apply sign_forest_array_ext
    intro j hj
    change j < 12 at hj
    have hv := (hrows j hj).2.2
    simpa [forsSignerPaths, hj] using hv
  simp only [hroots, hsecrets, hpaths, and_self]

end Extracted.Equiv
