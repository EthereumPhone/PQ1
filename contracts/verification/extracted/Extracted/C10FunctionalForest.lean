/- Forest caller values under the existing supplied backend interpretation.
   The transmitted slot 12 is a root, with a separate leaf hash on recovery. -/
import Extracted.C10FunctionalBuilders
import Extracted.SignForestPhaseSpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalTrees
open Extracted.C10FunctionalBuilders Extracted.C10FunctionalBuildValues
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalForest

def indexWords (indices : Std.Array Std.U32 13#usize) : List Int :=
  indices.val.map (fun v => Int.ofNat v.val)

def nodeWords {n : Std.Usize} (nodes : Std.Array (Std.Array Std.U8 16#usize) n) :
    List (List Int) := nodes.val.map (fun v => byteInts v.val)

def pathWords (paths : Equiv.SignForestPaths) : List (List (List Int)) :=
  paths.val.map nodeWords

theorem index_words_get (indices : Std.Array Std.U32 13#usize) (j : Nat) (hj : j < 13) :
    (indexWords indices).getD j 0 = Int.ofNat (indices.val[j]!).val := by
  have hi : j < indices.val.length := by simpa using hj
  rw [indexWords, List.getD_eq_getElem _ _ (by simpa using hi),
    List.getElem_map, getElem!_pos indices.val j hi]

theorem forest_root_value (seed sk : Std.Array Std.U8 32#usize) (ht tree : Std.U32) :
    byteInts (Equiv.forsRootNode seed sk ht tree 11 0).val =
      fors_root_value suppliedBackend (byteInts seed.val) (byteInts sk.val)
        (Int.ofNat ht.val) (Int.ofNat tree.val) := by
  rw [fors_node_value seed sk ht tree 11 0 (by decide) (by decide),
    fors_root_value, root_eq_node]

theorem signing_path_value (seed sk : Std.Array Std.U8 32#usize) (ht tree leaf : Std.U32)
    (hl : leaf.val < 2048) :
    nodeWords (Equiv.forsSigningPath seed sk ht tree leaf) =
      fors_auth_values suppliedBackend (byteInts seed.val) (byteInts sk.val)
        (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) := by
  apply fors_path_value seed sk ht tree leaf _ hl
  intro k hk
  simp [Equiv.forsSigningPath, hk]

theorem signer_secrets_value (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) :
    nodeWords (Equiv.forsSignerSecrets seed sk ht indices) =
      forest_sign_secrets suppliedBackend (byteInts seed.val) (byteInts sk.val)
        (Int.ofNat ht.val) (indexWords indices) := by
  simp only [nodeWords, Equiv.forsSignerSecrets, List.map_map, Function.comp_def]
  rw [List.range_succ (n := 12), List.map_append, List.map_singleton]
  unfold forest_sign_secrets
  congr 1
  · apply List.map_congr_left
    intro j hj
    have hj12 := List.mem_range.mp hj
    have hjval : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j :=
      Nat.mod_eq_of_lt (by omega)
    rw [if_pos hj12, fors_secret_pure_value, hjval, index_words_get indices j (by omega)]
  · rw [if_neg (by omega), forest_root_value]
    rfl

theorem signer_paths_value (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    pathWords (Equiv.forsSignerPaths seed sk ht indices) =
      forest_sign_paths suppliedBackend (byteInts seed.val) (byteInts sk.val)
        (Int.ofNat ht.val) (indexWords indices) := by
  simp only [pathWords, Equiv.forsSignerPaths, forest_sign_paths, List.map_map, Function.comp_def]
  apply List.map_congr_left
  intro j hj
  have hj12 := List.mem_range.mp hj
  have hjval : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j :=
    Nat.mod_eq_of_lt (by omega)
  rw [signing_path_value seed sk ht _ _ (hi j hj12), hjval,
    index_words_get indices j (by omega)]

theorem signing_recovery_value (seed sk : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hl : leaf.val < 2048) :
    byteInts (Equiv.forsRootNode seed sk ht tree 11 0).val =
      fors_recover_value suppliedBackend (byteInts seed.val) (Int.ofNat ht.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val)
        (fors_secret_value suppliedBackend (byteInts sk.val) (Int.ofNat ht.val)
          (Int.ofNat tree.val) (Int.ofNat leaf.val))
        (fors_auth_values suppliedBackend (byteInts seed.val) (byteInts sk.val)
          (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat leaf.val)) := by
  let secret := Equiv.forsSecretPure sk ht tree leaf
  let path := Equiv.forsSigningPath seed sk ht tree leaf
  have hp : ∀ k, k < 11 → path.val[k]! =
      Equiv.forsRootNode seed sk ht tree k (Equiv.forsAuthSibling leaf.val k) := by
    intro k hk
    simp [path, Equiv.forsSigningPath, hk]
  obtain ⟨r, he, hr⟩ := WP.spec_imp_exists (Equiv.fors_recovery_spec seed ht tree leaf secret path)
  have hv := extracted_fors_recover_value seed ht tree leaf secret path
  rw [he] at hv
  simp only [WP.spec_ok] at hv
  rw [hr, Equiv.fors_auth_recovery_root seed sk ht tree leaf hl secret path rfl hp] at hv
  rw [show secret = Equiv.forsSecretPure sk ht tree leaf from rfl,
    fors_secret_pure_value] at hv
  change byteInts (Equiv.forsRootNode seed sk ht tree 11 0).val =
    fors_recover_value _ _ _ _ _ _ (nodeWords path) at hv
  rw [signing_path_value seed sk ht tree leaf hl] at hv
  exact hv

theorem signer_roots_value (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    nodeWords (Equiv.forsSignerRoots seed sk ht) =
      forest_recover_roots suppliedBackend (byteInts seed.val) (Int.ofNat ht.val)
        (indexWords indices)
        (forest_sign_secrets suppliedBackend (byteInts seed.val) (byteInts sk.val)
          (Int.ofNat ht.val) (indexWords indices))
        (forest_sign_paths suppliedBackend (byteInts seed.val) (byteInts sk.val)
          (Int.ofNat ht.val) (indexWords indices)) := by
  simp only [nodeWords, Equiv.forsSignerRoots, List.map_map, Function.comp_def]
  rw [List.range_succ (n := 12), List.map_append, List.map_singleton]
  unfold forest_recover_roots
  congr 1
  · apply List.map_congr_left
    intro j hj
    have hj12 := List.mem_range.mp hj
    have hjval : (⟨BitVec.ofNat 32 j⟩ : Std.U32).val = j :=
      Nat.mod_eq_of_lt (by omega)
    rw [if_pos hj12, signing_recovery_value seed sk ht _ _ (hi j hj12), hjval,
      index_words_get indices j (by omega)]
    simp only [forest_sign_secrets, forest_sign_paths]
    rw [List.getD_eq_getElem _ _ (by simp; omega),
      List.getD_eq_getElem _ _ (by simp; omega)]
    rw [List.getElem_append]
    simp only [List.length_map, List.length_range, dif_pos hj12, List.getElem_map,
      List.getElem_range, index_words_get indices j (by omega)]
  · rw [if_neg (by omega)]
    have hv := fors_leaf_pure_value seed ht 12#u32 0#u32
      (Equiv.forsRootNode seed sk ht 12#u32 11 0)
    rw [forest_root_value] at hv
    simp only [show (12#u32).val = 12 by rfl, show (0#u32).val = 0 by rfl] at hv
    rw [hv]
    simp [forest_sign_secrets]

theorem forest_compression_value (seed : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (roots : Equiv.SignForestNodes) :
    sphincs_c10.fors.compute_fors_pk seed ht roots ⦃ r =>
      byteInts r.val = forest_compress_value suppliedBackend (byteInts seed.val)
        (Int.ofNat ht.val) (nodeWords roots) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.fors_pk_spec seed ht roots
  rw [hr, multi_pure_value]
  have ha : Equiv.forsPkAdrs ht = pathAddress 0 ht.val 4 0 0 0 := rfl
  rw [ha, path_address_value]
  rfl

/-- The actual factored signer phase, followed by its actual compression caller.
    Shuffle affects execution order but all transmitted values remain positional. -/
theorem extracted_forest_sign_value (seed sk : Std.Array Std.U8 32#usize) (ht : Std.U32)
    (indices : Std.Array Std.U32 13#usize) (progress : sphincs_c10.hypertree.ProgressSink)
    (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (hi : ∀ j, j < 12 → (indices.val[j]!).val < 2048) :
    Equiv.signerForsPhase seed sk ht indices progress shuffle 12#usize ⦃ r =>
      sphincs_c10.fors.compute_fors_pk seed ht r.1 ⦃ pk =>
        (nodeWords r.2.1, pathWords r.2.2, byteInts pk.val) =
          forest_sign_value suppliedBackend (byteInts seed.val) (byteInts sk.val)
            (Int.ofNat ht.val) (indexWords indices) ⦄ ⦄ := by
  let* ⟨roots, secrets, paths, hr⟩ ← Equiv.signer_fors_phase_spec seed sk ht indices progress shuffle hi
  simp only [Prod.mk.injEq] at hr
  obtain ⟨rfl, rfl, rfl⟩ := hr
  let* ⟨pk, hp⟩ ← forest_compression_value seed ht (Equiv.forsSignerRoots seed sk ht)
  rw [hp, signer_secrets_value, signer_paths_value seed sk ht indices hi,
    signer_roots_value seed sk ht indices hi]
  rfl

end Extracted.C10FunctionalForest
