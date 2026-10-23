/- Actual tree construction against the shared values, under the existing
   supplied-backend and callback-free release extraction interpretation. -/
import Extracted.C10FunctionalBuildValues
import Extracted.C10FunctionalTrees
import Extracted.ForsAuthOutside
import Extracted.XmssAuthOutside

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10AddressInputBridge
open Extracted.C10FunctionalWots Extracted.C10FunctionalTrees
open Extracted.C10FunctionalBuildValues C10Representation
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalBuilders

theorem fors_node_value (seed secret : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) (h idx : Nat) (hh : h ≤ 11) (hi : idx < 2^(11-h)) :
    byteInts (Equiv.forsRootNode seed secret ht tree h idx).val =
      recursiveNode suppliedBackend (byteInts seed.val) 0 (Int.ofNat ht.val) 3
        (Int.ofNat tree.val)
        (fors_tree_leaves suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat ht.val) (Int.ofNat tree.val)) h idx := by
  induction h generalizing idx with
  | zero =>
    have hi' : idx < 2048 := by norm_num at hi; exact hi
    let leaf : Std.U32 := ⟨BitVec.ofNat 32 idx⟩
    have hv : leaf.val = idx := Nat.mod_eq_of_lt (by omega)
    have hl := fors_leaf_pure_value seed ht tree leaf (Equiv.forsSecretPure secret ht tree leaf)
    rw [fors_secret_pure_value] at hl
    simpa [Equiv.forsRootNode, hv, recursiveNode, fors_tree_leaves, hi', leaf] using hl
  | succ h ih =>
    have hs : 11-h = (11-(h+1))+1 := by omega
    have hp : 2^(11-h) = 2^(11-(h+1))*2 := by rw [hs, pow_succ]
    rw [Equiv.forsRootNode, pair_pure_value]
    change tree_pair_value _ _ (byteInts (pathAddress 0 ht.val 3 tree.val (h+1) idx).val) _ _ = _
    rw [path_address_value, ih (2*idx) (by omega) (by omega),
      ih (2*idx+1) (by omega) (by omega), recursiveNode]
    rfl

theorem merkle_node_value (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (h idx : Nat) (hh : h ≤ 9) (hi : idx < 2^(9-h)) :
    byteInts (Equiv.xmssRootNode seed secret layer tree h idx).val =
      recursiveNode suppliedBackend (byteInts seed.val) (Int.ofNat layer.val)
        (Int.ofNat tree.val) 2 0
        (merkle_tree_leaves suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat layer.val) (Int.ofNat tree.val)) h idx := by
  induction h generalizing idx with
  | zero =>
    have hi' : idx < 512 := by norm_num at hi; exact hi
    let leaf : Std.U32 := ⟨BitVec.ofNat 32 idx⟩
    have hv : leaf.val = idx := Nat.mod_eq_of_lt (by omega)
    have hl := keygen_pure_value seed secret layer tree leaf
    simpa [Equiv.xmssRootNode, hv, recursiveNode, merkle_tree_leaves, hi', leaf] using hl
  | succ h ih =>
    have hs : 9-h = (9-(h+1))+1 := by omega
    have hp : 2^(9-h) = 2^(9-(h+1))*2 := by rw [hs, pow_succ]
    rw [Equiv.xmssRootNode, pair_pure_value]
    change tree_pair_value _ _ (byteInts (pathAddress layer.val tree.val 2 0 (h+1) idx).val) _ _ = _
    rw [path_address_value, ih (2*idx) (by omega) (by omega),
      ih (2*idx+1) (by omega) (by omega), recursiveNode]
    rfl

theorem extracted_fors_root_value (seed secret : Std.Array Std.U8 32#usize)
    (ht tree : Std.U32) :
    sphincs_c10.fors.compute_fors_root seed secret ht tree ⦃ r =>
      byteInts r.val = fors_root_value suppliedBackend (byteInts seed.val)
        (byteInts secret.val) (Int.ofNat ht.val) (Int.ofNat tree.val) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.fors_compute_root_spec seed secret ht tree
  rw [hr, fors_node_value seed secret ht tree 11 0 (by decide) (by decide),
    fors_root_value, root_eq_node]

theorem extracted_merkle_root_value (seed secret : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct_lo pct_hi : Std.U8) :
    sphincs_c10.merkle.compute_subtree_root seed secret layer tree progress pct_lo pct_hi ⦃ r =>
      byteInts r.val = merkle_root_value suppliedBackend (byteInts seed.val)
        (byteInts secret.val) (Int.ofNat layer.val) (Int.ofNat tree.val) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.xmss_compute_root_spec seed secret layer tree progress pct_lo pct_hi
  rw [hr, merkle_node_value seed secret layer tree 9 0 (by decide) (by decide),
    merkle_root_value, root_eq_node]

theorem fors_path_value (seed secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (path : Std.Array (Std.Array Std.U8 16#usize) 11#usize)
    (hleaf : leaf.val < 2048)
    (hp : ∀ k, k < 11 → path.val[k]! =
      Equiv.forsRootNode seed secret ht tree k (Equiv.forsAuthSibling leaf.val k)) :
    path.val.map (fun v => byteInts v.val) =
      fors_auth_values suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) := by
  apply List.ext_getElem (by simp [fors_auth_values, auth_length, path.property])
  intro k hk hr
  have hkp : k < path.val.length := by simpa using hk
  have hk11 : k < 11 := by simpa using hkp
  simp only [List.getElem_map]
  rw [← getElem!_pos path.val k hkp, hp k hk11]
  rw [← List.getD_eq_getElem _ (List.replicate 16 0) hr]
  unfold fors_auth_values
  rw [auth_nat_node _ _ _ _ _ _ 11 _ leaf.val k hk11 hleaf]
  exact fors_node_value seed secret ht tree k (Equiv.forsAuthSibling leaf.val k)
    (by omega) (sibling_nat_range leaf.val k 11 hk11 hleaf)

theorem merkle_path_value (seed secret : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (path : Std.Array (Std.Array Std.U8 16#usize) 9#usize) (hleaf : leaf.val < 512)
    (hp : ∀ k, k < 9 → path.val[k]! =
      Equiv.xmssRootNode seed secret layer tree k (Equiv.xmssAuthSibling leaf.val k)) :
    path.val.map (fun v => byteInts v.val) =
      merkle_auth_values suppliedBackend (byteInts seed.val) (byteInts secret.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) := by
  apply List.ext_getElem (by simp [merkle_auth_values, auth_length, path.property])
  intro k hk hr
  have hkp : k < path.val.length := by simpa using hk
  have hk9 : k < 9 := by simpa using hkp
  simp only [List.getElem_map]
  rw [← getElem!_pos path.val k hkp, hp k hk9]
  rw [← List.getD_eq_getElem _ (List.replicate 16 0) hr]
  unfold merkle_auth_values
  rw [auth_nat_node _ _ _ _ _ _ 9 _ leaf.val k hk9 hleaf]
  exact merkle_node_value seed secret layer tree k (Equiv.xmssAuthSibling leaf.val k)
    (by omega) (sibling_nat_range leaf.val k 9 hk9 hleaf)

theorem extracted_fors_sign_valid_values (seed secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (hleaf : leaf.val < 2048) :
    sphincs_c10.fors.sign_fors_tree seed secret ht tree leaf ⦃ r =>
      (byteInts r.1.val, r.2.val.map (fun v => byteInts v.val)) =
        fors_sign_values suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) ⦄ := by
  let* ⟨s, path, hs, hp⟩ ← Equiv.fors_sign_tree_spec seed secret ht tree leaf hleaf
  rw [hs, fors_secret_pure_value, fors_path_value seed secret ht tree leaf path hleaf hp]
  rfl

theorem extracted_merkle_build_valid_value (seed secret : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct_lo pct_hi : Std.U8)
    (hleaf : leaf.val < 512) :
    sphincs_c10.merkle.build_subtree_with_auth seed secret layer tree leaf progress pct_lo pct_hi
      ⦃ r => (r.1.val.map (fun v => byteInts v.val), byteInts r.2.val) =
        merkle_build_value suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) ⦄ := by
  let* ⟨path, root, hr, hp⟩ ← Equiv.xmss_build_auth_spec seed secret layer leaf tree progress pct_lo pct_hi hleaf
  rw [hr, merkle_path_value seed secret layer leaf tree path hleaf hp,
    merkle_node_value seed secret layer tree 9 0 (by decide) (by decide)]
  unfold merkle_build_value merkle_root_value
  rw [root_eq_node]

/-- No valid-leaf premise: an out-of-tree U32 target keeps the actual zero path. -/
theorem extracted_fors_sign_values (seed secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    sphincs_c10.fors.sign_fors_tree seed secret ht tree leaf ⦃ r =>
      (byteInts r.1.val, r.2.val.map (fun v => byteInts v.val)) =
        fors_sign_values suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) ⦄ := by
  by_cases hl : leaf.val < 2048
  · exact extracted_fors_sign_valid_values seed secret ht tree leaf hl
  let* ⟨s, path, hs, hp⟩ ← Equiv.fors_sign_tree_outside_spec seed secret ht tree leaf (by omega)
  rw [hs, hp, fors_secret_pure_value]
  unfold fors_sign_values fors_auth_values
  rw [auth_outside _ _ _ _ _ _ 11 _ _ (by simp [fors_tree_leaves])
    (by change (2048:Int) ≤ (leaf.val:Int); omega)]
  simp [byteInts]

/-- Full U32 target domain under the existing callback-free release extraction. -/
theorem extracted_merkle_build_value (seed secret : Std.Array Std.U8 32#usize)
    (layer leaf : Std.U32) (tree : Std.U64)
    (progress : sphincs_c10.hypertree.ProgressSink) (pct_lo pct_hi : Std.U8) :
    sphincs_c10.merkle.build_subtree_with_auth seed secret layer tree leaf progress pct_lo pct_hi
      ⦃ r => (r.1.val.map (fun v => byteInts v.val), byteInts r.2.val) =
        merkle_build_value suppliedBackend (byteInts seed.val) (byteInts secret.val)
          (Int.ofNat layer.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) ⦄ := by
  by_cases hl : leaf.val < 512
  · exact extracted_merkle_build_valid_value seed secret layer leaf tree progress pct_lo pct_hi hl
  let* ⟨path, root, hr, hp⟩ ← Equiv.xmss_build_auth_outside_spec seed secret layer leaf tree
    progress pct_lo pct_hi (by omega)
  rw [hr, hp, merkle_node_value seed secret layer tree 9 0 (by decide) (by decide)]
  unfold merkle_build_value merkle_root_value merkle_auth_values
  rw [root_eq_node, auth_outside _ _ _ _ _ _ 9 _ _ (by simp [merkle_tree_leaves])
    (by change (512:Int) ≤ (leaf.val:Int); omega)]
  simp [byteInts]

end Extracted.C10FunctionalBuilders
