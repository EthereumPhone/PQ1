/- Complete release signer against the shared functional values and bytes.
   Existing backend/progress/paired-printer interpretation boundaries remain. -/
import Extracted.C10FunctionalSignerValues
import Extracted.C10FunctionalSignerSerialization

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalForest Extracted.C10FunctionalLayer
open Extracted.C10FunctionalSignerHeader Extracted.C10FunctionalSignatureBytes
open Extracted.C10FunctionalSignerValues Extracted.C10FunctionalSignerSerialization
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalSigner

attribute [local irreducible] List.range C10Representation.layer_sign_slot
  Equiv.forsSignerSecrets Equiv.forsSignerPaths Equiv.forsSignerRoots
  Equiv.xmssRootNode Equiv.xmssSigningPath Equiv.pureWotsSign
  Equiv.serializedForest Equiv.serializedNonce Equiv.serializedLayer
  C10Representation.forest_sign_value C10Representation.layer_recover_value
  Extracted.C10FunctionalSignerValues.layerResult

theorem paired_actions {α β : Type} (a : Result α) (b : Result β)
    (first : α → WordLayer) (second : β → WordLayer) (node0 node1 : List Int)
    (aa : Result (WordLayer × List Int)) (bb : List Int → Result (WordLayer × List Int))
    (ha : (do let x ← a; .ok (first x,node0)) = aa)
    (hb : (do let y ← b; .ok (second y,node1)) = bb node0)
    (r : List Int) (secrets : List (List Int)) (paths : List (List (List Int))) :
    (do let x ← a; let y ← b; .ok (r,secrets,paths,[first x,second y])) =
      (do let (x,node) ← aa; let (y,_) ← bb node; .ok (r,secrets,paths,[x,y])) := by
  rw [← ha]
  simp only [bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]
  rw [bind_eq_iff]
  intro x _
  rw [← hb]
  simp only [bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]

theorem fields_factor (seed secret : Std.Array Std.U8 32#usize)
    (r current : Std.Array Std.U8 16#usize) (secrets : Equiv.ForsSecrets) (paths : Equiv.ForsAuthPaths)
    (idx : Std.U32) :
    (do let signed ← Equiv.pureSignHypertree seed secret
          (Equiv.serializedForest (Equiv.serializedNonce r) secrets paths) current idx
        .ok (parsedSignatureWords signed.1)) =
      (do let (chains0,count0) ← Equiv.pureWotsSign seed secret (Equiv.signLayerId ⟨0,by decide⟩)
            (UScalar.cast .U64 (Equiv.signNextTree idx)) (Equiv.signLeaf idx) current
          let (chains1,count1) ← Equiv.pureWotsSign seed secret (Equiv.signLayerId ⟨1,by decide⟩)
            (UScalar.cast .U64 (Equiv.signNextTree (Equiv.signNextTree idx)))
            (Equiv.signLeaf (Equiv.signNextTree idx))
            (Equiv.xmssRootNode seed secret (Equiv.signLayerId ⟨0,by decide⟩)
              (UScalar.cast .U64 (Equiv.signNextTree idx)) 9 0)
          .ok (byteInts r.val,nodeWords secrets,pathWords paths,
            [(nodeWords chains0,Int.ofNat count0.val,
              nodeWords (Equiv.xmssSigningPath seed secret (Equiv.signLayerId ⟨0,by decide⟩)
                (UScalar.cast .U64 (Equiv.signNextTree idx)) (Equiv.signLeaf idx))),
             (nodeWords chains1,Int.ofNat count1.val,
              nodeWords (Equiv.xmssSigningPath seed secret (Equiv.signLayerId ⟨1,by decide⟩)
                (UScalar.cast .U64 (Equiv.signNextTree (Equiv.signNextTree idx)))
                (Equiv.signLeaf (Equiv.signNextTree idx))))])) := by
  simp only [Equiv.pureSignHypertree, Equiv.pureSignLayer, bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]
  rw [bind_eq_iff]
  rintro ⟨chains0,count0⟩ _
  simp only [bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]
  rw [bind_eq_iff]
  rintro ⟨chains1,count1⟩ _
  simp only [bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]
  congr 1
  exact serialized_full_words r secrets paths chains0 count0 _ chains1 count1 _

theorem hypertree_result (seed secret : Std.Array Std.U8 32#usize)
    (r current : Std.Array Std.U8 16#usize) (secrets : Equiv.ForsSecrets) (paths : Equiv.ForsAuthPaths)
    (idx : Std.U32) (progress : sphincs_c10.hypertree.ProgressSink) :
    (do let signed ← Equiv.pureSignHypertree seed secret
          (Equiv.serializedForest (Equiv.serializedNonce r) secrets paths) current idx
        .ok (parsedSignatureWords signed.1)) =
      (do let (first,node) ← layerResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
            0 (Int.ofNat idx.val/512) (Int.ofNat idx.val%512) (byteInts current.val)
          let (second,_) ← layerResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
            1 (Int.ofNat idx.val/512/512) (Int.ofNat idx.val/512%512) node
          .ok (byteInts r.val,nodeWords secrets,pathWords paths,[first,second])) := by
  rw [fields_factor]
  have h0 := indexed_layer_result seed secret ⟨0,by decide⟩ idx current progress
  have h1 := second_indexed_layer_result seed secret idx
    (Equiv.xmssRootNode seed secret (Equiv.signLayerId ⟨0,by decide⟩)
      (UScalar.cast .U64 (Equiv.signNextTree idx)) 9 0) progress
  exact paired_actions _ _ _ _ _ _ _ _ h0 h1 _ _ _

theorem forest_values (seed secret : Std.Array Std.U8 32#usize)
    (digest : Std.Array Std.U8 32#usize) :
    (nodeWords (Equiv.forsSignerSecrets seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest)),
      pathWords (Equiv.forsSignerPaths seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest)),
      byteInts (th_multi_pure seed (Equiv.forsPkAdrs (Equiv.headerHtIndex digest))
        (Array.to_slice (Equiv.forsSignerRoots seed secret (Equiv.headerHtIndex digest)))).val) =
      forest_sign_value suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (ht_field (byteInts digest.val)) (digest_fors_indices (byteInts digest.val)) := by
  have hb := (C10FunctionalVerifier.header_forest_bounds digest).1
  have hv := forest_compression_value seed (Equiv.headerHtIndex digest)
    (Equiv.forsSignerRoots seed secret (Equiv.headerHtIndex digest))
  obtain ⟨pk,he,hp⟩ := WP.spec_imp_exists (Equiv.fors_pk_spec seed (Equiv.headerHtIndex digest)
    (Equiv.forsSignerRoots seed secret (Equiv.headerHtIndex digest)))
  rw [he] at hv
  simp only [WP.spec_ok] at hv
  rw [hp] at hv
  rw [hv, signer_secrets_value, signer_paths_value _ _ _ _ hb,
    signer_roots_value _ _ _ _ hb, C10FunctionalVerifier.header_ht_word,
    C10FunctionalVerifier.header_index_words]
  rw [forest_sign_value, forest_recover_value]

theorem finish_result (seed secret : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) :
    (do let signed ← Equiv.pureSignHypertree seed secret
          (Equiv.serializedForest (Equiv.serializedNonce r)
            (Equiv.forsSignerSecrets seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest))
            (Equiv.forsSignerPaths seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest)))
          (th_multi_pure seed (Equiv.forsPkAdrs (Equiv.headerHtIndex digest))
            (Array.to_slice (Equiv.forsSignerRoots seed secret (Equiv.headerHtIndex digest))))
          (Equiv.headerHtIndex digest)
        .ok (parsedSignatureWords signed.1)) =
      finishResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (byteInts r.val) (byteInts digest.val) := by
  have ht := hypertree_result seed secret r
    (th_multi_pure seed (Equiv.forsPkAdrs (Equiv.headerHtIndex digest))
      (Array.to_slice (Equiv.forsSignerRoots seed secret (Equiv.headerHtIndex digest))))
    (Equiv.forsSignerSecrets seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest))
    (Equiv.forsSignerPaths seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest))
    (Equiv.headerHtIndex digest) progress
  rw [ht, C10FunctionalVerifier.header_ht_word]
  have hv := forest_values seed secret digest
  rw [finishResult, ← hv]

noncomputable def actualFinishWords (seed secret : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize) : Result WordSignature := do
  let signed ← Equiv.pureSignHypertree seed secret
    (Equiv.serializedForest (Equiv.serializedNonce r)
      (Equiv.forsSignerSecrets seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest))
      (Equiv.forsSignerPaths seed secret (Equiv.headerHtIndex digest) (Equiv.headerForsIndices digest)))
    (th_multi_pure seed (Equiv.forsPkAdrs (Equiv.headerHtIndex digest))
      (Array.to_slice (Equiv.forsSignerRoots seed secret (Equiv.headerHtIndex digest))))
    (Equiv.headerHtIndex digest)
  .ok (parsedSignatureWords signed.1)

theorem pure_release_words (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize)) :
    (do let out ← Equiv.pureReleaseSign secret message seed root random
        .ok (parsedSignatureWords out)) =
      (do let (r,digest) ← Equiv.pureGrindR secret message seed root random
          actualFinishWords (pad16Pure seed) secret r digest) := by
  simp only [Equiv.pureReleaseSign, Equiv.pureWholeSignNodes, actualFinishWords,
    bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]
  rw [bind_eq_iff]
  rintro ⟨r,digest⟩ _
  simp only [uncurry_apply_pair, bind_assoc_eq, bind_tc_ok]
  rw [bind_eq_iff]
  rintro ⟨sig,node⟩ _
  rfl

theorem mapped_action {α β γ : Type} (a : Result α) (g : α → β) (b : Result β)
    (ha : (do let x ← a; .ok (g x)) = b) (f : α → Result γ) (k : β → Result γ)
    (hk : ∀ x, f x = k (g x)) :
    (do let x ← a; f x) = (do let y ← b; k y) := by
  rw [← ha]
  simp only [bind_assoc_eq, bind_tc_ok]
  rw [bind_eq_iff]
  intro x _
  exact hk x

theorem mapped_pair_action {α β γ δ ε : Type} (a : Result (α × β))
    (g : α → γ) (h : β → δ) (b : Result (γ × δ))
    (ha : (do let (x,y) ← a; .ok (g x,h y)) = b)
    (f : α → β → Result ε) (k : γ → δ → Result ε)
    (hk : ∀ x y, f x y = k (g x) (h y)) :
    (do let (x,y) ← a; f x y) = (do let (u,v) ← b; k u v) := by
  rw [← ha]
  simp only [bind_assoc_eq, bind_tc_ok, uncurry_apply_pair]
  rw [bind_eq_iff]
  rintro ⟨x,y⟩ _
  exact hk x y

attribute [local irreducible] actualFinishWords Equiv.pureGrindR Equiv.pureReleaseSign
  Equiv.pureWholeSignNodes Equiv.pureSignHypertree headerResult finishResult
  sphincs_c10.hypertree.release_sign_inner

theorem actual_finish_result (seed secret : Std.Array Std.U8 32#usize)
    (r : Std.Array Std.U8 16#usize) (digest : Std.Array Std.U8 32#usize)
    (progress : sphincs_c10.hypertree.ProgressSink) :
    actualFinishWords seed secret r digest =
      finishResult suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (byteInts r.val) (byteInts digest.val) := by
  unfold actualFinishWords
  exact finish_result seed secret r digest progress

theorem pure_signer_result (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize))
    (progress : sphincs_c10.hypertree.ProgressSink) :
    (do let out ← Equiv.pureReleaseSign secret message seed root random
        .ok (parsedSignatureWords out)) =
      signerResult suppliedBackend (byteInts (pad16Pure seed).val) (byteInts (pad16Pure root).val)
        (byteInts secret.val) (byteInts (optionalBytes random)) (byteInts message.val) := by
  rw [pure_release_words]
  unfold signerResult
  apply mapped_pair_action _ _ _ _ (pure_header_result secret message seed root random)
  intro r digest
  exact actual_finish_result (pad16Pure seed) secret r digest progress

theorem actual_release_words (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize))
    (progress : sphincs_c10.hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    (do let out ← sphincs_c10.hypertree.release_sign_inner secret seed root message random progress shuffle
        .ok (parsedSignatureWords out)) =
      (do let out ← Equiv.pureReleaseSign secret message seed root random
          .ok (parsedSignatureWords out)) :=
  congrArg (fun action => do let out ← action; .ok (parsedSignatureWords out))
    (Equiv.firmware_sign_release_pure secret message seed root random progress shuffle)

/-- Complete actual release caller: exact common words or the same bounded
    assertion failure. No valid-key, successful-search or root-equality premise. -/
theorem extracted_signer_result (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize))
    (progress : sphincs_c10.hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    (do let out ← sphincs_c10.hypertree.release_sign_inner secret seed root message random progress shuffle
        .ok (parsedSignatureWords out)) =
      signerResult suppliedBackend (byteInts (pad16Pure seed).val) (byteInts (pad16Pure root).val)
        (byteInts secret.val) (byteInts (optionalBytes random)) (byteInts message.val) :=
  (actual_release_words secret message seed root random progress shuffle).trans
    (pure_signer_result secret message seed root random progress)

/-- Exact returned bytes, including both full-width WOTS counters. -/
theorem extracted_signer_bytes (secret message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize))
    (progress : sphincs_c10.hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    (do let out ← sphincs_c10.hypertree.release_sign_inner secret seed root message random progress shuffle
        .ok (signatureBytes out)) =
      (do let sig ← signerResult suppliedBackend (byteInts (pad16Pure seed).val) (byteInts (pad16Pure root).val)
            (byteInts secret.val) (byteInts (optionalBytes random)) (byteInts message.val)
          .ok (encodeWords sig)) := by
  rw [← extracted_signer_result secret message seed root random progress shuffle]
  simp only [bind_assoc_eq, bind_tc_ok]
  rw [bind_eq_iff]
  intro sig _
  rw [parsed_bytes]

end Extracted.C10FunctionalSigner
