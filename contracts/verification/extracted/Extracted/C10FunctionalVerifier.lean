/- Complete verifier values under the existing deterministic backend model.
   Actual decoding and rejection continuations are retained. Paired printers,
   backend interpretation and probability transfer remain separate boundaries. -/
import Extracted.C10FunctionalForestRecover
import Extracted.C10FunctionalLayer
import Extracted.SignHeaderSpec
import Extracted.WholeVerifierSpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalForest
open Extracted.C10FunctionalForestRecover Extracted.C10FunctionalLayer
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalVerifier

theorem header_index_words (digest : Std.Array Std.U8 32#usize) :
    indexWords (Equiv.headerForsIndices digest) = digest_fors_indices (byteInts digest.val) := by
  apply List.ext_getElem
  · simp [indexWords, digest_fors_indices]
  intro j hj hj'
  have hb : j < 13 := by simpa [digest_fors_indices] using hj'
  rw [← List.getD_eq_getElem _ 0 hj, index_words_get _ j hb]
  simp only [digest_fors_indices, List.getElem_map, List.getElem_range,
    fors_field, byteInts, digest_word_window, Equiv.header_fors_index_val digest j hb]
  simp only [Nat.mul_comm, show (2 : Nat)^11 = 2048 by decide]

theorem header_ht_word (digest : Std.Array Std.U8 32#usize) :
    Int.ofNat (Equiv.headerHtIndex digest).val = ht_field (byteInts digest.val) := by
  rw [ht_field, byteInts, digest_word_window, Equiv.header_ht_index_val]
  rfl

/-- The actual digest-derived indices discharge the forest precondition. -/
theorem header_forest_bounds (digest : Std.Array Std.U8 32#usize) :
    (∀ j, j < 12 → (Equiv.headerForsIndices digest).val[j]!.val < 2048) ∧
      0 ≤ ht_field (byteInts digest.val) ∧ ht_field (byteInts digest.val) < 262144 := by
  refine ⟨?_, ?_⟩
  · intro j hj
    rw [Equiv.header_fors_index_val digest j (by omega)]
    exact Nat.mod_lt _ (by decide)
  rw [← header_ht_word]
  have h := (Equiv.header_indices_bound digest).2
  simp only [Int.ofNat_eq_natCast]
  omega

theorem digest_value (seed root : Std.Array Std.U8 16#usize)
    (message : Std.Array Std.U8 32#usize) (sig : Equiv.C10Signature) :
    byteInts (Equiv.verifierDigest seed root message sig).val =
      verifier_digest suppliedBackend (byteInts (pad16Pure seed).val)
        (byteInts (pad16Pure root).val) (byteInts (Equiv.verifierRandomizer sig).val)
        (byteInts message.val) := by
  unfold verifier_digest suppliedBackend
  rw [← pad_node_value, ← hmsg_input_value, bytesOfInts_byteInts]
  rfl

theorem byte_node_injective (a b : Std.Array Std.U8 16#usize) :
    byteInts a.val = byteInts b.val ↔ a = b := by
  constructor
  · intro h
    apply Subtype.ext
    have h' := congrArg bytesOfInts h
    simpa only [bytesOfInts_byteInts] using h'
  · rintro rfl; rfl

/-- Reify the existing raw layer, including rejected WOTS sums, using the
    actual extracted recovery calls and the common functional expression. -/
theorem raw_layer_values (seed : Std.Array Std.U8 32#usize) (sig : Equiv.C10Signature)
    (layer : Fin 2) (idx : Std.U32) (current : Std.Array Std.U8 16#usize) :
    ∃ node : Std.Array Std.U8 16#usize,
      Equiv.toSpecNode node = Equiv.rawLayerRoot seed sig layer idx.val (Equiv.toSpecNode current) ∧
      byteInts node.val = layer_recover_value suppliedBackend (byteInts seed.val)
        (Int.ofNat layer.val) (Int.ofNat (idx.val / 512)) (Int.ofNat (idx.val % 512))
        (byteInts current.val) (nodeWords (Equiv.parsedLayerChains sig layer))
        (Int.ofNat (Equiv.parsedLayerCount sig layer).val) (nodeWords (Equiv.parsedLayerAuth sig layer)) := by
  let lid := Equiv.signLayerId layer
  let tree := UScalar.cast .U64 (Equiv.signNextTree idx)
  let leaf := Equiv.signLeaf idx
  have hl : lid.val = layer.val := by
    change layer.val % 4294967296 = layer.val
    exact Nat.mod_eq_of_lt (by have := layer.isLt; omega)
  have ht : tree.val = idx.val / 512 := by
    dsimp only [tree]
    rw [UScalar.cast_val_eq, Equiv.sign_next_tree_val]
    change (idx.val / 512) % 18446744073709551616 = idx.val / 512
    exact Nat.mod_eq_of_lt (by have h : idx.val < 4294967296 := idx.hBounds; omega)
  have hp : leaf.val = idx.val % 512 := Equiv.sign_leaf_val idx
  obtain ⟨node, he, hv⟩ := WP.spec_imp_exists
    (layer_recovery_value seed lid tree leaf current (Equiv.parsedLayerChains sig layer)
      (Equiv.parsedLayerCount sig layer) (Equiv.parsedLayerAuth sig layer))
  have hs : (do let pk ← sphincs_c10.wots.pk_from_sig seed lid tree leaf current
                    (Equiv.parsedLayerChains sig layer) (Equiv.parsedLayerCount sig layer)
                sphincs_c10.merkle.verify_auth_path seed lid tree pk leaf (Equiv.parsedLayerAuth sig layer))
      ⦃ r => Equiv.toSpecNode r = Equiv.rawLayerRoot seed sig layer idx.val (Equiv.toSpecNode current) ⦄ := by
    let* ⟨pk, hpk⟩ ← Equiv.firmware_pk_from_sig_matches_vendored seed lid tree leaf current
      (Equiv.parsedLayerChains sig layer) (Equiv.parsedLayerCount sig layer)
    let* ⟨r, hr⟩ ← Equiv.firmware_verify_auth_path_matches_vendored seed lid tree pk leaf
      (Equiv.parsedLayerAuth sig layer)
    rw [hr, hpk, hl, ht, hp]
    rfl
  rw [he] at hs
  refine ⟨node, hs, ?_⟩
  simpa only [hl, ht, hp] using hv

theorem extracted_hypertree_value (seed : Std.Array Std.U8 32#usize)
    (sig : Equiv.C10Signature) (current : Std.Array Std.U8 16#usize) (idx : Std.U32) :
    sphincs_c10.hypertree.verify_loop3 {start := 0#u32, «end» := 2#u32}
      sig seed 2336#usize current idx ⦃ node =>
        byteInts node.val = hypertree_recover_value suppliedBackend (byteInts seed.val)
          (Int.ofNat idx.val) (byteInts current.val)
          (nodeWords (Equiv.parsedLayerChains sig ⟨0, by decide⟩))
          (Int.ofNat (Equiv.parsedLayerCount sig ⟨0, by decide⟩).val)
          (nodeWords (Equiv.parsedLayerAuth sig ⟨0, by decide⟩))
          (nodeWords (Equiv.parsedLayerChains sig ⟨1, by decide⟩))
          (Int.ofNat (Equiv.parsedLayerCount sig ⟨1, by decide⟩).val)
          (nodeWords (Equiv.parsedLayerAuth sig ⟨1, by decide⟩)) ⦄ := by
  obtain ⟨first, hf, hvf⟩ := raw_layer_values seed sig ⟨0, by decide⟩ idx current
  obtain ⟨second, hs, hvs⟩ := raw_layer_values seed sig ⟨1, by decide⟩ (Equiv.signNextTree idx) first
  have he : Equiv.toSpecNode second = Equiv.rawHypertreeRoot seed sig idx.val (Equiv.toSpecNode current) := by
    simpa only [Equiv.sign_next_tree_val, hf, Equiv.rawHypertreeRoot] using hs
  let* ⟨node, hn⟩ ← Equiv.firmware_verify_hypertree_loop seed sig current idx
  have hnode : node = second := (Equiv.toSpecNode_inj node second).mp (hn.trans he.symm)
  rw [hnode, hvs, hvf]
  simp only [hypertree_recover_value, hypertree_first_value, Equiv.sign_next_tree_val,
    Int.ofNat_eq_natCast, Int.natCast_ediv, Int.natCast_emod, Int.cast_ofNat_Int, Int.reduceSub]

theorem verifier_head_values (seed root : Std.Array Std.U8 16#usize)
    (message : Std.Array Std.U8 32#usize) (sig : Equiv.C10Signature) :
    Equiv.verifierHead seed root message sig = .ok
      (pad16Pure seed, Equiv.headerForsIndices (Equiv.verifierDigest seed root message sig),
       Equiv.headerHtIndex (Equiv.verifierDigest seed root message sig), 16#usize) := by
  obtain ⟨s, hs, hse⟩ := WP.spec_imp_exists (sphincs_c10.pad16_pure_spec seed)
  obtain ⟨r, hr, hre⟩ := WP.spec_imp_exists (sphincs_c10.pad16_pure_spec root)
  obtain ⟨rb, hb, hbe⟩ := WP.spec_imp_exists (sphincs_c10.pad16_pure_spec (Equiv.verifierRandomizer sig))
  obtain ⟨⟨i, randomizer⟩, hi, hie, hrandom⟩ := WP.spec_imp_exists (Equiv.readVerifierRandomizer_spec sig)
  rw [hse] at hs
  rw [hre] at hr
  rw [hbe] at hb
  dsimp only at hie hrandom
  rw [hie, hrandom] at hi
  simp only [Equiv.verifierHead, hs, hr, hi, hb, sphincs_c10.hash.h_msg_spec,
    bind_tc_ok, uncurry_apply_pair]
  rw [← Equiv.verifierDigest, Equiv.header_fors_indices_pure, Equiv.header_ht_index_pure]
  rfl

def verifierResult (f : List Int → List Int) (seed root message : List Int)
    (sig : WordSignature) : Bool :=
  let digest := verifier_digest f seed root sig.1 message
  let first := sig.2.2.2.getD 0 ([], 0, [])
  let second := sig.2.2.2.getD 1 ([], 0, [])
  if fors_zero_field digest = 0 then
    decide (pad_node (verifier_recover_value f seed digest sig.2.1 sig.2.2.1
      first.1 first.2.1 first.2.2 second.1 second.2.1 second.2.2) = root)
  else false

-- Keep the complete expression symbolic during endpoint unification. A wrong
-- layer selection must be a proof mismatch, not eager expansion of recovery.
attribute [local irreducible] verifier_recover_value
  Equiv.parsedLayerChains Equiv.parsedLayerCount Equiv.parsedLayerAuth

theorem decoded_verifier_result (seed root : Std.Array Std.U8 16#usize)
    (message : Std.Array Std.U8 32#usize) (sig : Equiv.C10Signature) :
    sphincs_c10.hypertree.verify seed root message sig ⦃ r =>
      r = verifierResult suppliedBackend (byteInts (pad16Pure seed).val)
        (byteInts (pad16Pure root).val) (byteInts message.val)
        (word_decode (signatureBytes sig)) ⦄ := by
  let digest := Equiv.verifierDigest seed root message sig
  have hd : verifier_digest suppliedBackend (byteInts (pad16Pure seed).val)
      (byteInts (pad16Pure root).val) (byteInts (Equiv.verifierRandomizer sig).val)
      (byteInts message.val) = byteInts digest.val := (digest_value seed root message sig).symm
  have hzfield : fors_zero_field (byteInts digest.val) =
      Int.ofNat ((Equiv.headerForsIndices digest).val[12]!.val) := by
    rw [fors_zero_field, byteInts, digest_word_window, Equiv.header_fors_index_val digest 12 (by decide)]
    rfl
  have layers : List.ofFn (parsedLayerWords sig) =
      [parsedLayerWords sig ⟨0, by decide⟩, parsedLayerWords sig ⟨1, by decide⟩] := rfl
  have hni : nodeInts = fun (node : Std.Array Std.U8 16#usize) => byteInts node.val := rfl
  simp only [verifierResult, signature_words, parsedSignatureWords, layers,
    List.getD_cons_zero, List.getD_cons_succ, parsedLayerWords, hni, hd]
  by_cases hz : fors_zero_field (byteInts digest.val) = 0
  · have hzero : (Equiv.headerForsIndices digest).val[12]!.val = 0 := by
      rw [hzfield] at hz
      exact Int.ofNat_eq_zero.mp hz
    rw [if_pos hz, Equiv.verifier_head_factor, verifier_head_values]
    simp only [bind_tc_ok, uncurry_apply_pair]
    rw [Equiv.verifier_after_head_factor _ _ _ _ _ hzero]
    let* ⟨pk, hpk⟩ ← extracted_forest_recover_value (pad16Pure seed) (Equiv.headerHtIndex digest)
      (Equiv.headerForsIndices digest) (Equiv.parsedForsSecrets sig) (Equiv.parsedForsAuth sig)
    unfold Equiv.verifierHypertreeContinuation
    have hc : UScalar.cast .U32 sphincs_c10.params.D = 2#u32 := by
      apply UScalar.eq_of_val_eq
      rw [UScalar.cast_val_eq]
      simp only [sphincs_c10.params.D]
      decide
    simp only [lift, hc, bind_tc_ok]
    let* ⟨node, hn⟩ ← extracted_hypertree_value (pad16Pure seed) sig pk (Equiv.headerHtIndex digest)
    let* ⟨r, hr⟩ ← Equiv.verifier_node_compare node root
    have hforest : byteInts pk.val = digest_forest_value suppliedBackend
        (byteInts (pad16Pure seed).val) (byteInts digest.val)
        (nodeWords (Equiv.parsedForsSecrets sig)) (pathWords (Equiv.parsedForsAuth sig)) := by
      rw [hpk, header_ht_word, header_index_words]
      rfl
    rw [header_ht_word, hforest] at hn
    change r = decide (pad_node (verifier_recover_value suppliedBackend
      (byteInts (pad16Pure seed).val) (byteInts digest.val)
      (nodeWords (Equiv.parsedForsSecrets sig)) (pathWords (Equiv.parsedForsAuth sig))
      (nodeWords (Equiv.parsedLayerChains sig ⟨0, by decide⟩))
      (Int.ofNat (Equiv.parsedLayerCount sig ⟨0, by decide⟩).val)
      (nodeWords (Equiv.parsedLayerAuth sig ⟨0, by decide⟩))
      (nodeWords (Equiv.parsedLayerChains sig ⟨1, by decide⟩))
      (Int.ofNat (Equiv.parsedLayerCount sig ⟨1, by decide⟩).val)
      (nodeWords (Equiv.parsedLayerAuth sig ⟨1, by decide⟩))) = byteInts (pad16Pure root).val)
    rw [verifier_recover_value, ← hn, pad_node_value]
    unfold pad_node
    have hcompare : (byteInts node.val ++ List.replicate 16 0 =
        byteInts root.val ++ List.replicate 16 0) ↔ node = root := by
      constructor
      · intro h
        exact (byte_node_injective node root).mp (List.append_cancel_right h)
      · intro h; rw [h]
    cases r with
    | false =>
      have hne : ¬ (byteInts node.val ++ List.replicate 16 0 =
          byteInts root.val ++ List.replicate 16 0) := fun h => Bool.false_ne_true (hr.mpr (hcompare.mp h))
      exact (decide_eq_false hne).symm
    | true =>
      exact (decide_eq_true (hcompare.mpr (hr.mp rfl))).symm
  · rw [if_neg hz]
    have hbad : (Equiv.digestWord digest >>> 132) % 2^11 ≠ 0 := by
      intro hbad
      apply hz
      rw [fors_zero_field, byteInts, digest_word_window, hbad]
      rfl
    exact Equiv.firmware_verify_rejects_nonzero_fors seed root message sig hbad

end Extracted.C10FunctionalVerifier
