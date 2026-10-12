/- The constructed shuffled forest recovers the same compression input. -/
import Extracted.SignForestPhaseSpec
import Extracted.HypertreeContinuationSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192
attribute [local irreducible] forsRootNode forsSecretPure SphincsCVerify.Spec.Sha256Impl.sha256Bytes
attribute [local irreducible] SphincsCVerify.Spec.Fors.reconstructRoot

theorem signer_normal_recovery (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (j : Nat) (hj : j < 12)
    (hi : (indices.val[j]!).val < 2048) :
    hypertree.reconstruct_fors_root seed ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)
      ((forsSignerSecrets seed sk ht indices).val[j]!)
      ((forsSignerPaths seed sk ht indices).val[j]!) ⦃ r =>
        r = forsRootNode seed sk ht ⟨BitVec.ofNat 32 j⟩ 11 0 ⦄ := by
  have hs : (forsSignerSecrets seed sk ht indices).val[j]! =
      forsSecretPure sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!) := by
    simp [forsSignerSecrets, hj, show j < 13 by omega]
  have hp : (forsSignerPaths seed sk ht indices).val[j]! =
      forsSigningPath seed sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!) := by
    simp [forsSignerPaths, hj]
  let* ⟨r, hr⟩ ← fors_recovery_spec seed ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)
    ((forsSignerSecrets seed sk ht indices).val[j]!)
    ((forsSignerPaths seed sk ht indices).val[j]!)
  rw [hr]
  apply fors_auth_recovery_root seed sk ht _ _ hi _ _ hs
  intro h hh
  rw [hp]
  simp [forsSigningPath, hh]

theorem signer_normal_reference (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (j : Nat) (hj : j < 12)
    (hi : (indices.val[j]!).val < 2048) :
    forsNormalRoot seed ht indices (forsSignerSecrets seed sk ht indices)
      (forsSignerPaths seed sk ht indices) j =
      toSpecNode (forsRootNode seed sk ht ⟨BitVec.ofNat 32 j⟩ 11 0) := by
  obtain ⟨r, hr, hval⟩ := WP.spec_imp_exists (signer_normal_recovery seed sk ht indices j hj hi)
  obtain ⟨s, hs, hspec⟩ := WP.spec_imp_exists (firmware_fors_recovery_matches_vendored
    seed ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)
    ((forsSignerSecrets seed sk ht indices).val[j]!)
    ((forsSignerPaths seed sk ht indices).val[j]!))
  rw [hr] at hs
  have he : r = s := Result.ok.inj hs
  rw [← he, hval] at hspec
  have hcast : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := by
    exact Nat.mod_eq_of_lt (by omega)
  simpa only [forsNormalRoot, hcast] using hspec.symm

/-- Verification of the emitted forest components reaches exactly the roots
    constructed by signing, including the special last-slot hash. -/
theorem signer_forest_recovery (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    forsForestPhase seed ht indices (forsSignerSecrets seed sk ht indices)
      (forsSignerPaths seed sk ht indices) ⦃ pk =>
      pk = th_multi_pure seed (forsPkAdrs ht) (Array.to_slice (forsSignerRoots seed sk ht)) ⦄ := by
  unfold forsForestPhase
  let* ⟨roots, hroots⟩ ← firmware_fors_normal_roots seed ht indices
    (forsSignerSecrets seed sk ht indices)
    (Array.repeat 13#usize (Array.repeat 16#usize 0#u8)) (forsSignerPaths seed sk ht indices)
  simp only [lift, core.convert.num.FromU64U32.from]
  let* ⟨adrs, ha⟩ ← make_adrs_spec 0#u32
    (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) params.ADRS_FORS_TREE 12#u32 0#u32 0#u32 0#u32
  have hwide : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
    BitVec.toNat_setWidth_of_le (by decide)
  have hadrs : forsRecoveryAdrs ht 12#u32 0 0 = adrs := by
    apply forsRecoveryAdrs_eq_of_map_val
    simpa only [params.ADRS_FORS_TREE, hwide] using ha
  let* ⟨last, hl⟩ ← Array.index_usize_spec (forsSignerSecrets seed sk ht indices) 12#usize (by scalar_tac)
  have hlast : last = forsRootNode seed sk ht 12#u32 11 0 := by
    rw [hl]
    simp [forsSignerSecrets]
  let* ⟨padded, hp⟩ ← pad16_spec last
  let* ⟨lastRoot, hlr⟩ ← hash.th_spec seed adrs padded
  let* ⟨allRoots, hall⟩ ← Array.update_spec roots 12#usize lastRoot (by scalar_tac)
  have he : allRoots = forsSignerRoots seed sk ht := by
    apply sign_forest_array_ext
    intro j hj
    change j < 13 at hj
    rw [hall, Array.set_val_eq]
    simp only [show (12#usize).val = 12 by simp]
    by_cases hn : j < 12
    · rw [List.set_getElem!_ne _ _ _ _ (by omega)]
      have hv := hroots j hj
      rw [if_pos hn, signer_normal_reference seed sk ht indices j hn (hi j hn)] at hv
      have heq := (toSpecNode_inj _ _).mp hv
      simpa [forsSignerRoots, hj, hn] using heq
    · have hj12 : j = 12 := by omega
      subst j
      rw [List.set_getElem!_eq _ _ _ _ ⟨by rw [roots.property]; decide, rfl⟩,
        hlr, hp, hlast, ← hadrs]
      simp [forsSignerRoots]
  rw [he]
  exact fors_pk_spec seed ht (forsSignerRoots seed sk ht)

/-- Actual signing components and actual verifier components terminate and
    agree with the actual signer-side compression call. -/
theorem firmware_sign_fors_recovers_pk (seed sk : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (indices : Std.Array Std.U32 13#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    signerForsPhase seed sk ht indices progress shuffle 12#usize ⦃ signed =>
      forsForestPhase seed ht indices signed.2.1 signed.2.2 ⦃ recovered =>
        fors.compute_fors_pk seed ht signed.1 ⦃ expected => recovered = expected ⦄ ⦄ ⦄ := by
  obtain ⟨signed, hrun, hsigned⟩ := WP.spec_imp_exists
    (signer_fors_phase_spec seed sk ht indices progress shuffle hi)
  rw [hsigned] at hrun
  rw [hrun]
  simp only [WP.spec_ok]
  let* ⟨recovered, hr⟩ ← signer_forest_recovery seed sk ht indices hi
  let* ⟨expected, he⟩ ← fors_pk_spec seed ht (forsSignerRoots seed sk ht)
  rw [hr, he]

end Extracted.Equiv
