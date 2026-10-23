/- The verifier's actual factored forest block, for arbitrary represented
   indices, secrets and authentication paths, against the paired recovery. -/
import Extracted.C10FunctionalForest
import Extracted.SignForestRecovery

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalTrees Extracted.C10FunctionalForest
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes
attribute [local irreducible] SphincsCVerify.Spec.Fors.reconstructRoot

namespace Extracted.C10FunctionalForestRecover

theorem node_words_get {n : Std.Usize} (nodes : Std.Array (Std.Array Std.U8 16#usize) n)
    (j : Nat) (hj : j < n.val) (fallback : List Int) :
    (nodeWords nodes).getD j fallback = byteInts (nodes.val[j]!).val := by
  have hb : j < nodes.val.length := by rwa [nodes.property]
  rw [nodeWords, List.getD_eq_getElem _ _ (by simpa using hb), List.getElem_map,
    getElem!_pos nodes.val j hb]

theorem path_words_get (paths : Equiv.SignForestPaths) (j : Nat) (hj : j < 12) :
    (pathWords paths).getD j [] = nodeWords (paths.val[j]!) := by
  have hb : j < paths.val.length := by simpa using hj
  rw [pathWords, List.getD_eq_getElem _ _ (by simpa using hb), List.getElem_map,
    getElem!_pos paths.val j hb]

theorem normal_root_value (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (secrets : Equiv.SignForestNodes)
    (paths : Equiv.SignForestPaths) (j : Nat) (hj : j < 12)
    (root : Std.Array Std.U8 16#usize)
    (hr : Equiv.toSpecNode root = Equiv.forsNormalRoot seed ht indices secrets paths j) :
    byteInts root.val = fors_recover_value suppliedBackend (byteInts seed.val) (Int.ofNat ht.val)
      (Int.ofNat j) (Int.ofNat (indices.val[j]!).val)
      (byteInts (secrets.val[j]!).val) (nodeWords (paths.val[j]!)) := by
  have hjval : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j := Nat.mod_eq_of_lt (by omega)
  obtain ⟨r, he, hv⟩ := WP.spec_imp_exists (extracted_fors_recover_value seed ht
    ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!) (secrets.val[j]!) (paths.val[j]!))
  have hs := Equiv.firmware_fors_recovery_matches_vendored seed ht
    ⟨BitVec.ofNat 32 j⟩ (indices.val[j]!) (secrets.val[j]!) (paths.val[j]!)
  rw [he] at hs
  simp only [WP.spec_ok, hjval] at hs
  have heq : root = r := (Equiv.toSpecNode_inj root r).mp (by
    exact hr.trans (by simpa only [Equiv.forsNormalRoot] using hs.symm))
  rw [heq]
  simpa only [hjval, nodeWords] using hv

theorem extracted_forest_recover_value (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (secrets : Equiv.SignForestNodes)
    (paths : Equiv.SignForestPaths) :
    Equiv.forsForestPhase seed ht indices secrets paths ⦃ pk =>
      byteInts pk.val = forest_recover_value suppliedBackend (byteInts seed.val) (Int.ofNat ht.val)
        (indexWords indices) (nodeWords secrets) (pathWords paths) ⦄ := by
  unfold Equiv.forsForestPhase
  let* ⟨roots, hroots⟩ ← Equiv.firmware_fors_normal_roots seed ht indices secrets
    (Std.Array.repeat 13#usize (Std.Array.repeat 16#usize 0#u8)) paths
  simp only [lift, core.convert.num.FromU64U32.from]
  let* ⟨adrs, ha⟩ ← Equiv.make_adrs_spec 0#u32
    (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64) sphincs_c10.params.ADRS_FORS_TREE 12#u32 0#u32 0#u32 0#u32
  have hwide : (⟨BitVec.setWidth 64 ht.bv⟩ : Std.U64).val = ht.val :=
    BitVec.toNat_setWidth_of_le (by decide)
  have hadrs : Equiv.forsRecoveryAdrs ht 12#u32 0 0 = adrs := by
    apply Equiv.forsRecoveryAdrs_eq_of_map_val
    simpa only [sphincs_c10.params.ADRS_FORS_TREE, hwide] using ha
  let* ⟨last, hl⟩ ← Std.Array.index_usize_spec secrets 12#usize (by scalar_tac)
  let* ⟨padded, hp⟩ ← Equiv.pad16_spec last
  let* ⟨lastRoot, hlast⟩ ← sphincs_c10.hash.th_spec seed adrs padded
  let* ⟨allRoots, hall⟩ ← Std.Array.update_spec roots 12#usize lastRoot (by scalar_tac)
  let* ⟨pk, hpk⟩ ← forest_compression_value seed ht allRoots
  rw [hpk]
  unfold forest_recover_value
  congr 1
  apply List.ext_getElem
  · simp [nodeWords, forest_recover_roots, allRoots.property]
  intro j hj hj'
  have hj13 : j < 13 := by simpa [nodeWords, allRoots.property] using hj
  rw [← List.getD_eq_getElem _ [] hj, node_words_get allRoots j hj13,
    hall, Std.Array.set_val_eq]
  simp only [show (12#usize).val = 12 from rfl]
  unfold forest_recover_roots
  rw [List.getElem_append]
  by_cases hn : j < 12
  · rw [List.set_getElem!_ne _ _ _ _ (by omega)]
    simp only [List.length_map, List.length_range, dif_pos hn, List.getElem_map, List.getElem_range]
    rw [index_words_get indices j hj13, node_words_get secrets j hj13, path_words_get paths j hn]
    exact normal_root_value seed ht indices secrets paths j hn _
      (by simpa only [if_pos hn] using hroots j hj13)
  · have hj12 : j = 12 := by omega
    subst j
    rw [List.set_getElem!_eq _ _ _ _ ⟨by rw [roots.property]; decide, rfl⟩,
      hlast, hp, ← hadrs]
    have hv := fors_leaf_pure_value seed ht 12#u32 0#u32 last
    simp only [show (0#u32).val = 0 from rfl, show (12#u32).val = 12 from rfl] at hv
    rw [hv]
    simp only [List.length_map, List.length_range, Nat.lt_irrefl, dif_neg, Nat.sub_self, List.getElem_cons_zero]
    rw [node_words_get secrets 12 (by decide), hl]
    rw [← getElem!_pos secrets.val 12 (by rw [secrets.property]; decide)]
    rfl

end Extracted.C10FunctionalForestRecover
