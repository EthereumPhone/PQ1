/- The release-assertion configuration of the actual signer caller.
   Opaque dependencies retain their existing models; this is neither a proof
   of release-compiled dependencies nor of the secure wrapper or machine code. -/
import Extracted.SignReleaseLoop
import Extracted.SignWholeSpec
open Aeneas Aeneas.Std Result
namespace Extracted.Equiv
open sphincs_c10
noncomputable section
set_option maxHeartbeats 200000
set_option maxRecDepth 8192
set_option pp.explicit true
attribute [local irreducible] fors.grind_r pureGrindR forsRootNode forsSecretPure forsSigningPath
  xmssRootNode wotsSignChains forsSignerSecrets forsSignerPaths forsSignerRoots
  serializedForest serializedNonce pureSignHypertree
  SphincsCVerify.Spec.Sha256Impl.sha256Bytes

def releaseAfterForest (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (ht : Std.U32) (roots secrets : SignForestNodes)
    (paths : SignForestPaths) : Result C10Signature := do
  let (sig3,offset) ← signerSerializeForest sig secrets paths
  let pk ← fors.compute_fors_pk seed ht roots
  let d ← lift (UScalar.cast .U32 params.D)
  let out ← hypertree.release_sign_inner_loop3 {start := 0#u32, «end» := d}
    sk progress shuffle seed sig3 offset pk ht
  hypertree.report progress 100#u8
  .ok out

def releaseCallerComposition (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    Result C10Signature := do
  let (r,digest) ← fors.grind_r sk seed root msg opt
  let sig ← hypertree.write16 (Array.repeat 4008#usize 0#u8) 0#usize r
  let indices ← fors.extract_fors_indices digest
  let ht ← fors.extract_ht_index digest
  let (roots,secrets,paths) ← signerForsPhase (pad16Pure seed) sk ht indices progress shuffle 12#usize
  releaseAfterForest sk (pad16Pure seed) progress shuffle sig ht roots secrets paths

theorem release_caller_factor (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.release_sign_inner sk seed root msg opt progress shuffle =
      releaseCallerComposition sk msg seed root opt progress shuffle := by
  obtain ⟨p,hp,hpv⟩ := WP.spec_imp_exists (pad16_pure_spec seed)
  rw [hpv] at hp
  simp only [hypertree.release_sign_inner, releaseCallerComposition, releaseAfterForest,
    signerForsPhase, signerSerializeForest, hypertree.write16, hp, header_offset_add,
    header_last_sub, hypertree.report, bind_tc_ok, bind_assoc_eq, bind_eq_iff,
    Prod.forall, uncurry_apply_pair, forall_const, implies_true]

theorem release_after_forest_pure (sk seed : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (sig : C10Signature) (ht : Std.U32) (roots secrets : SignForestNodes)
    (paths : SignForestPaths) :
    releaseAfterForest sk seed progress shuffle sig ht roots secrets paths =
      (do let (out,_) ← pureSignHypertree seed sk (serializedForest sig secrets paths)
            (th_multi_pure seed (forsPkAdrs ht) (Array.to_slice roots)) ht
          .ok out) := by
  obtain ⟨out,hr,he⟩ := WP.spec_imp_exists (firmware_serialize_forest sig secrets paths)
  rw [he] at hr
  obtain ⟨pk,hpk,hvalue⟩ := WP.spec_imp_exists (fors_pk_spec seed ht roots)
  rw [hvalue] at hpk
  have hc : UScalar.cast .U32 2#usize = 2#u32 := by
    apply UScalar.eq_of_val_eq
    rw [UScalar.cast_val_eq]
    decide
  simp only [releaseAfterForest, hr, hpk, params.D, lift, hc, bind_tc_ok, uncurry_apply_pair]
  rw [firmware_release_sign_hypertree_loop]
  simp only [bind_assoc_eq, bind_eq_iff, Prod.forall, uncurry_apply_pair,
    hypertree.report, bind_tc_ok, forall_const, implies_true]

def pureWholeSignNodes (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    Result (C10Signature × Std.Array Std.U8 16#usize) := do
  let (r,digest) ← pureGrindR sk msg seed root opt
  let s := pad16Pure seed
  let ht := headerHtIndex digest
  let indices := headerForsIndices digest
  pureSignHypertree s sk
    (serializedForest (serializedNonce r) (forsSignerSecrets s sk ht indices)
      (forsSignerPaths s sk ht indices))
    (th_multi_pure s (forsPkAdrs ht) (Array.to_slice (forsSignerRoots s sk ht))) ht

def pureReleaseSign (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    Result C10Signature := do
  let (sig,_) ← pureWholeSignNodes sk msg seed root opt
  .ok sig

/-- Unconditional Result equality: no debug root check and no assumed success. -/
theorem firmware_sign_release_pure (sk msg : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (progress : hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    hypertree.release_sign_inner sk seed root msg opt progress shuffle =
      pureReleaseSign sk msg seed root opt := by
  rw [release_caller_factor]
  unfold releaseCallerComposition pureReleaseSign pureWholeSignNodes
  rw [firmware_grind_r_pure]
  simp only [bind_assoc_eq]
  rw [bind_eq_iff]
  rintro ⟨r,digest⟩ _
  obtain ⟨out,hw,he⟩ := WP.spec_imp_exists
    (firmware_write16 (Array.repeat 4008#usize 0#u8) 0#usize r (by decide))
  have hout : out = serializedNonce r := by
    simpa only [serializedNonce] using signatureWrites_eq _ _ 0 16 _ he
  rw [hout] at hw
  simp only [uncurry_apply_pair, hw, header_fors_indices_pure, header_ht_index_pure, bind_tc_ok]
  obtain ⟨signed,hs,hvalue⟩ := WP.spec_imp_exists
    (signer_fors_phase_spec (pad16Pure seed) sk (headerHtIndex digest)
      (headerForsIndices digest) progress shuffle (by
        intro j hj
        rw [header_fors_index_val digest j (by omega)]
        exact Nat.mod_lt _ (by decide)))
  rw [hvalue] at hs
  simp only [hs, bind_tc_ok]
  exact release_after_forest_pure sk (pad16Pure seed) progress shuffle (serializedNonce r)
    (headerHtIndex digest) _ _ _

end
end Extracted.Equiv
