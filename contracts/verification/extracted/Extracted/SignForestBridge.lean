/- Pointwise correspondence of every emitted forest component to the faithful
   reference signer. Backend and callback boundaries are unchanged. -/
import Extracted.SignForestRecovery
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10 SphincsCVerify.Spec
set_option maxHeartbeats 3000000
set_option maxRecDepth 8192
attribute [local irreducible] forsRootNode forsSecretPure SphincsCVerify.Spec.Sha256Impl.sha256Bytes

/-- The actual FORS construction has no dependence on its scheduling seed. -/
theorem firmware_sign_fors_shuffle_independent (seed sk : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (indices : Std.Array Std.U32 13#usize)
    (progress : hypertree.ProgressSink) (a b : shuffle.ShuffleSeed)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    signerForsPhase seed sk ht indices progress a 12#usize =
      signerForsPhase seed sk ht indices progress b 12#usize := by
  obtain ⟨ra, hra, ha⟩ := WP.spec_imp_exists (signer_fors_phase_spec seed sk ht indices progress a hi)
  obtain ⟨rb, hrb, hb⟩ := WP.spec_imp_exists (signer_fors_phase_spec seed sk ht indices progress b hi)
  rw [hra, hrb, ha, hb]

/-- All thirteen transmitted values and all twelve paths are specified
    independently of the extracted loop; the special final value is a root. -/
theorem firmware_sign_fors_matches_vendored (seed sk : Std.Array Std.U8 32#usize)
    (ht : Std.U32) (indices : Std.Array Std.U32 13#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    signerForsPhase seed sk ht indices progress shuffle 12#usize ⦃ signed =>
      (∀ j, j < 13 → toSpecNode (signed.2.1.val[j]!) =
        Signer.forsSigningValue (toSpecDigest seed) (toSpecDigest sk) ht.val j (indices.val[j]!).val) ∧
      (∀ j, j < 12 → ((signed.2.2.val[j]!).val.map toSpecNode).toArray =
        forsMtAuthPath (toSpecDigest seed) (UInt64.ofNat ht.val) (UInt32.ofNat j)
          (fun leaf => forsSecret (toSpecDigest sk) (UInt32.ofNat ht.val)
            (UInt32.ofNat j) (UInt32.ofNat leaf)) (indices.val[j]!).val) ⦄ := by
  obtain ⟨signed, hrun, hsigned⟩ := WP.spec_imp_exists
    (signer_fors_phase_spec seed sk ht indices progress shuffle hi)
  rw [hsigned] at hrun
  rw [hrun]
  simp only [WP.spec_ok]
  constructor
  · intro j hj
    by_cases hn : j < 12
    · have hcast : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := Nat.mod_eq_of_lt (by omega)
      have hv := fors_secret_pure_matches_vendored sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)
      simpa [forsSignerSecrets, Signer.forsSigningValue, K, hj, hn, show j ≠ 12 by omega, hcast] using hv
    · have he : j = 12 := by omega
      subst j
      have hv := fors_root_node_matches_vendored seed sk ht 12#u32 11 0 (by decide) (by decide)
      simpa [forsSignerSecrets, Signer.forsSigningValue, K, A] using hv
  · intro j hj
    have hp : (forsSignerPaths seed sk ht indices).val[j]! =
        forsSigningPath seed sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!) := by
      simp [forsSignerPaths, hj]
    have hcast : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := Nat.mod_eq_of_lt (by omega)
    have hv := fors_auth_path_matches_vendored seed sk ht ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!)
      ((forsSignerPaths seed sk ht indices).val[j]!) (hi j hj) (by
        intro h hh
        rw [hp]
        simp [forsSigningPath, hh])
    simpa only [hcast] using hv

end Extracted.Equiv
