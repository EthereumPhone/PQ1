/- Relate checked and release-configured signer callers under the same models.
   No caller-supplied root is silently treated as a generated key. -/
import Extracted.SignReleaseSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
attribute [local irreducible] forsRootNode forsSecretPure forsSigningPath
  xmssRootNode wotsSignChains forsSignerSecrets forsSignerPaths forsSignerRoots
  serializedForest serializedNonce pureSignHypertree
  SphincsCVerify.Spec.Sha256Impl.sha256Bytes

theorem whole_sign_nodes_root (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (out : C10Signature) (node : Std.Array Std.U8 16#usize)
    (h : pureWholeSignNodes sk msg seed root opt = .ok (out,node)) :
    node = xmssRootNode (pad16Pure seed) sk 1#u32 0#u64 9 0 := by
  unfold pureWholeSignNodes at h
  cases hn : pureGrindR sk msg seed root opt with
  | fail e => simp only [hn, bind_tc_fail] at h; cases h
  | div => simp only [hn, bind_tc_div] at h; cases h
  | ok pair =>
    rcases pair with ⟨r,digest⟩
    simp only [hn, bind_tc_ok, uncurry_apply_pair] at h
    apply firmware_sign_hypertree_top_root sk (pad16Pure seed) ()
      (Array.repeat 32#usize 0#u8) _ out _ node (headerHtIndex digest)
      4008#usize (header_indices_bound digest).2
    rw [firmware_sign_hypertree_loop, h]
    rfl

theorem checked_whole_nodes_factor (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) :
    pureWholeSign sk msg seed root opt progress =
      (do let (sig,node) ← pureWholeSignNodes sk msg seed root opt
          signerRootCheck root progress sig node) := by
  simp only [pureWholeSign, pureWholeSignNodes, pureSignerAfterForest, bind_assoc_eq,
    bind_eq_iff, Prod.forall, uncurry_apply_pair, forall_const, implies_true]

/-- Exact caller relation for every root and every Result, including exhausted
    searches. Only the checked configuration applies this last guard. -/
theorem firmware_sign_checked_release_relation (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.sign_inner sk seed root msg opt progress shuffle =
      (do let sig ← hypertree.release_sign_inner sk seed root msg opt progress shuffle
          signerRootCheck root progress sig (xmssRootNode (pad16Pure seed) sk 1#u32 0#u64 9 0)) := by
  rw [firmware_sign_whole_pure, firmware_sign_release_pure, checked_whole_nodes_factor]
  unfold pureReleaseSign
  simp only [bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨sig,node⟩ h
  simp only [uncurry_apply_pair, bind_tc_ok]
  rw [whole_sign_nodes_root sk msg seed root opt sig node h]

/-- For the key-generated root, removing the caller debug assertions changes
    neither returned bytes nor failure/divergence. Search success is not assumed. -/
theorem firmware_sign_release_valid_key (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hr : root = xmssRootNode (pad16Pure seed) sk 1#u32 0#u64 9 0) :
    hypertree.release_sign_inner sk seed root msg opt progress shuffle =
      hypertree.sign_inner sk seed root msg opt progress shuffle := by
  rw [firmware_sign_checked_release_relation, ← hr]
  simp only [signer_root_check_match]
  cases hypertree.release_sign_inner sk seed root msg opt progress shuffle <;> rfl

/-- The key precondition is discharged by the actual extracted key-root call. -/
theorem firmware_keygen_sign_release (sk msg : Std.Array Std.U8 32#usize)
    (seed : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    (do let root ← hypertree.compute_pk_root sk seed
        hypertree.release_sign_inner sk seed root msg opt progress shuffle) =
      (do let root ← hypertree.compute_pk_root sk seed
          hypertree.sign_inner sk seed root msg opt progress shuffle) := by
  obtain ⟨root,hr,hvalue⟩ := WP.spec_imp_exists (xmss_compute_pk_root_spec sk seed)
  rw [hr]
  simp only [bind_tc_ok]
  have hp : pad16p seed = pad16Pure seed := by unfold pad16Pure; rfl
  rw [hp] at hvalue
  exact firmware_sign_release_valid_key sk msg seed root opt progress shuffle hvalue

theorem firmware_sign_release_shuffle_independent (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (a b : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.release_sign_inner sk seed root msg opt progress a =
      hypertree.release_sign_inner sk seed root msg opt progress b := by
  rw [firmware_sign_release_pure, firmware_sign_release_pure]

theorem firmware_sign_release_nonce_exhausted (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hr : ∀ c : Std.U32, c.val < 10000000 →
      ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) msg opt c) :
    hypertree.release_sign_inner sk seed root msg opt progress shuffle = .fail .assertionFailure := by
  rw [firmware_sign_release_pure]
  unfold pureReleaseSign pureWholeSignNodes
  rw [← firmware_grind_r_pure, grind_r_exhausted sk msg seed root opt hr]
  rfl

end
end Extracted.Equiv
