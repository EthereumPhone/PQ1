/- Compose the actual signer from the first nonce through its final root check.
   This is a functional Result relation under the existing backend model. -/
import Extracted.SignHeaderSpec
import Extracted.SignForestPrefix
import Extracted.SignHypertreeCaller
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true
attribute [local irreducible] forsRootNode forsSecretPure forsSigningPath
  xmssRootNode wotsSignChains forsSignerSecrets forsSignerPaths forsSignerRoots
  serializedForest serializedNonce pureSignerAfterForest pureSignHypertree
  SphincsCVerify.Spec.Sha256Impl.sha256Bytes

def pureWholeSign (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) : Result C10Signature := do
  let (r,digest) ← pureGrindR sk msg seed root opt
  let s := pad16Pure seed
  let indices := headerForsIndices digest
  let ht := headerHtIndex digest
  pureSignerAfterForest sk s root progress
    (serializedForest (serializedNonce r) (forsSignerSecrets s sk ht indices)
      (forsSignerPaths s sk ht indices)) ht (forsSignerRoots s sk ht)

/-- Equality for every input: first accepted nonce, canonical forest, both
    first-count layers, exact byte layout, and the unchanged final check.
    Exhaustion and root mismatch are not replaced by assumed success. -/
theorem firmware_sign_whole_pure (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.sign_inner sk seed root msg opt progress shuffle =
      pureWholeSign sk msg seed root opt progress := by
  rw [firmware_sign_fors_prefix, firmware_sign_header_pure]
  unfold pureWholeSign
  simp only [bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨r,digest⟩ h
  have hz := grind_header_forced_zero sk msg seed root opt r digest h
  simp only [pureHeaderTail, uncurry_apply_pair, bind_tc_ok,
    signerAfterCanonicalForest, hz, if_true, hypertree.report]
  exact firmware_signer_after_forest_pure sk (pad16Pure seed) root progress shuffle
    (serializedNonce r) (headerHtIndex digest) (forsSignerRoots (pad16Pure seed) sk (headerHtIndex digest))
    (forsSignerSecrets (pad16Pure seed) sk (headerHtIndex digest) (headerForsIndices digest))
    (forsSignerPaths (pad16Pure seed) sk (headerHtIndex digest) (headerForsIndices digest))

/-- Schedule randomization cannot change the returned bytes or failure result. -/
theorem firmware_sign_whole_shuffle_independent (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (a b : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.sign_inner sk seed root msg opt progress a =
      hypertree.sign_inner sk seed root msg opt progress b := by
  rw [firmware_sign_whole_pure, firmware_sign_whole_pure]

/-- Bounded nonce exhaustion reaches the actual whole signer result. -/
theorem firmware_sign_nonce_exhausted (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hr : ∀ c : Std.U32, c.val < 10000000 →
      ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) msg opt c) :
    hypertree.sign_inner sk seed root msg opt progress shuffle = .fail .assertionFailure := by
  rw [firmware_sign_whole_pure]
  unfold pureWholeSign
  rw [← firmware_grind_r_pure, grind_r_exhausted sk msg seed root opt hr]
  simp only [bind_tc_fail]

/-- The final check can return only its input bytes and the matching root. -/
theorem signer_root_check_success (root node : Std.Array Std.U8 16#usize)
    (progress : hypertree.ProgressSink) (sig out : C10Signature)
    (h : signerRootCheck root progress sig node = .ok out) :
    out = sig ∧ node = root := by
  obtain ⟨len,hlen,he⟩ := WP.spec_imp_exists verifier_signature_len
  rw [he] at hlen
  obtain ⟨b,hb,hbeq⟩ := WP.spec_imp_exists (verifier_node_compare node root)
  unfold signerRootCheck at h
  simp only [hypertree.report, bind_tc_ok, hlen, massert, if_true, hb] at h
  cases b with
  | false => simp only [Bool.false_eq_true, if_false, core.fmt.Arguments.from_str,
      bind_tc_ok] at h; cases h
  | true =>
    simp only [if_true, Result.ok.injEq] at h
    exact ⟨h.symm,hbeq.mp rfl⟩

/-- Any successful whole signature retains the first accepted nonce bytes and
    passes the public-root check against the actual top key-generation tree. -/
theorem firmware_sign_whole_success (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (out : C10Signature)
    (h : hypertree.sign_inner sk seed root msg opt progress shuffle = .ok out) :
    ∃ c, FirstForsNonce sk msg seed root opt c ∧
      signatureNode out ⟨0,by decide⟩ = forsRandomizer sk msg opt c ∧
      root = xmssRootNode (pad16Pure seed) sk 1#u32 0#u64 9 0 := by
  rw [firmware_sign_whole_pure] at h
  unfold pureWholeSign at h
  cases hn : pureGrindR sk msg seed root opt with
  | fail e => simp only [hn, bind_tc_fail] at h; cases h
  | div => simp only [hn, bind_tc_div] at h; cases h
  | ok pair =>
    rcases pair with ⟨r,digest⟩
    simp only [hn, bind_tc_ok, uncurry_apply_pair] at h
    unfold pureSignerAfterForest at h
    let initial := serializedForest (serializedNonce r)
      (forsSignerSecrets (pad16Pure seed) sk (headerHtIndex digest) (headerForsIndices digest))
      (forsSignerPaths (pad16Pure seed) sk (headerHtIndex digest) (headerForsIndices digest))
    let current := th_multi_pure (pad16Pure seed) (forsPkAdrs (headerHtIndex digest))
      (Array.to_slice (forsSignerRoots (pad16Pure seed) sk (headerHtIndex digest)))
    change (do let (sig,node) ← pureSignHypertree (pad16Pure seed) sk initial current (headerHtIndex digest)
               signerRootCheck root progress sig node) = .ok out at h
    cases hl : pureSignHypertree (pad16Pure seed) sk initial current (headerHtIndex digest) with
    | fail e => simp only [hl, bind_tc_fail] at h; cases h
    | div => simp only [hl, bind_tc_div] at h; cases h
    | ok pair =>
      rcases pair with ⟨sig,node⟩
      simp only [hl, bind_tc_ok] at h
      obtain ⟨hs,hr⟩ := signer_root_check_success root node progress sig out h
      subst out
      have hloop : hypertree.sign_inner_loop3 {start := 0#u32, «end» := 2#u32}
          sk progress shuffle (pad16Pure seed) initial 2336#usize current (headerHtIndex digest) =
          .ok (sig,4008#usize,node) := by
        rw [firmware_sign_hypertree_loop, hl]
        rfl
      have hp := (firmware_sign_hypertree_success sk (pad16Pure seed) progress shuffle
        initial sig current node (headerHtIndex digest) 4008#usize hloop).2.2
      have ht := firmware_sign_hypertree_top_root sk (pad16Pure seed) progress shuffle
        initial sig current node (headerHtIndex digest) 4008#usize (header_indices_bound digest).2 hloop
      obtain ⟨c,hc,he,_⟩ := pure_grind_r_success sk msg seed root opt r digest hn
      refine ⟨c,hc,?_,hr.symm.trans ht⟩
      rw [← he]
      apply signatureNode_eq
      intro i
      have hi := i.isLt
      simp only [Nat.zero_add]
      rw [hp ⟨i.val,by omega⟩ (by dsimp; omega)]
      rw [serializedForest_preserves (serializedNonce r) _ _ ⟨i.val,by omega⟩ (Or.inl hi)]
      simpa only [if_pos hi] using serialized_nonce_bytes r ⟨i.val,by omega⟩

end
end Extracted.Equiv
