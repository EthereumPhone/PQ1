/- Functional FORS and XMSS recovery against the shared typed expressions.
   This uses the existing supplied SHA interpretation, not a sampled oracle. -/
import Extracted.C10FunctionalWots
import Extracted.ForsRecoverySpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10AddressInputBridge
open Extracted.C10FunctionalWots C10Representation
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalTrees

theorem pad16p_eq (x : Std.Array Std.U8 16#usize) : Equiv.pad16p x = pad16Pure x := by
  apply Subtype.ext
  rw [pad16Pure_val]
  rfl

theorem fors_secret_pure_value (secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    byteInts (Equiv.forsSecretPure secret ht tree leaf).val =
      fors_secret_value suppliedBackend (byteInts secret.val) (Int.ofNat ht.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) := by
  unfold fors_secret_value hash_bytes_node suppliedBackend
  rw [← fors_private_input_value, bytesOfInts_byteInts, Equiv.forsSecretPure, truncate16_val]
  simp [byteInts]

theorem extracted_fors_secret_value (secret : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) :
    sphincs_c10.hash.fors_secret secret ht tree leaf ⦃ r =>
      byteInts r.val = fors_secret_value suppliedBackend (byteInts secret.val)
        (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat leaf.val) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.fors_secret_spec secret ht tree leaf
  rw [hr]
  exact fors_secret_pure_value secret ht tree leaf

theorem pair_pure_value (seed address : Std.Array Std.U8 32#usize)
    (left right : Std.Array Std.U8 16#usize) :
    byteInts (th_pair_pure seed address (Equiv.pad16p left) (Equiv.pad16p right)).val =
      tree_pair_value suppliedBackend (byteInts seed.val) (byteInts address.val)
        (byteInts left.val) (byteInts right.val) := by
  rw [pad16p_eq, pad16p_eq]
  unfold tree_pair_value hash_bytes_node suppliedBackend
  rw [← pad_node_value left, ← pad_node_value right, ← pair_input_value,
    bytesOfInts_byteInts, th_pair_pure_def, truncate16_val]
  simp [byteInts]

def pathAddress (layer tree kind kp height idx : Nat) : Std.Array Std.U8 32#usize :=
  ⟨(Equiv.specMakeAdrs layer tree kind kp 0 height idx).map
      (fun n => (⟨BitVec.ofNat 8 n⟩ : Std.U8)), by
    simp [Equiv.specMakeAdrs, Equiv.u32be, Equiv.u64be]⟩

theorem path_address_value (layer tree kind kp height idx : Nat) :
    byteInts (pathAddress layer tree kind kp height idx).val =
      address_words (Int.ofNat layer) (Int.ofNat tree) (Int.ofNat kind)
        (Int.ofNat kp) 0 (Int.ofNat height) (Int.ofNat idx) := by
  have hu8 (n : Nat) : (⟨BitVec.ofNat 8 n⟩ : Std.U8).val = n % 256 := rfl
  rw [byteInts_as_nat]
  simp only [pathAddress, List.map_map, Function.comp_def, hu8]
  have hm : (Equiv.specMakeAdrs layer tree kind kp 0 height idx).map (fun n => n % 256) =
      Equiv.specMakeAdrs layer tree kind kp 0 height idx := by
    simp [Equiv.specMakeAdrs, Equiv.u32be, Equiv.u64be]
  change ((Equiv.specMakeAdrs layer tree kind kp 0 height idx).map
    (fun n => n % 256)).map Int.ofNat = _
  rw [hm, address_value]
  rfl

theorem fors_leaf_pure_value (seed : Std.Array Std.U8 32#usize)
    (ht tree leaf : Std.U32) (secret : Std.Array Std.U8 16#usize) :
    byteInts (th_pure seed (Equiv.forsRecoveryAdrs ht tree 0 leaf.val)
      (Equiv.pad16p secret)).val =
      fors_leaf_value suppliedBackend (byteInts seed.val) (Int.ofNat ht.val)
        (Int.ofNat tree.val) (Int.ofNat leaf.val) (byteInts secret.val) := by
  rw [pad16p_eq]
  change byteInts (th_pure seed (pathAddress 0 ht.val 3 tree.val 0 leaf.val)
    (pad16Pure secret)).val = _
  rw [hash_step_value, path_address_value]
  rfl

theorem path_zero (f : List Int → List Int) seed layer tree kind kp value idx auth :
    tree_path_value f seed layer tree kind kp value idx auth 0 = value := rfl

theorem path_succ (f : List Int → List Int) seed layer tree kind kp value idx auth n :
    tree_path_value f seed layer tree kind kp value idx auth (n+1) =
      tree_path_step f seed layer tree kind kp auth idx
        (tree_path_value f seed layer tree kind kp value idx auth n) n := by
  simp [tree_path_value, List.range_succ, List.foldl_append]

noncomputable def pathFold (seed : Std.Array Std.U8 32#usize)
    (layer tree kind kp : Nat) :
    List (Std.Array Std.U8 16#usize) → Std.Array Std.U8 16#usize → Nat → Nat →
    Std.Array Std.U8 16#usize
  | [], node, _, _ => node
  | sibling :: rest, node, idx, h =>
      let a := pathAddress layer tree kind kp (h+1) (idx/2)
      let next := if idx % 2 = 0 then
          th_pair_pure seed a (Equiv.pad16p node) (Equiv.pad16p sibling)
        else th_pair_pure seed a (Equiv.pad16p sibling) (Equiv.pad16p node)
      pathFold seed layer tree kind kp rest next (idx/2) (h+1)

theorem path_step_value (seed : Std.Array Std.U8 32#usize)
    (layer tree kind kp idx h : Nat) (node : Std.Array Std.U8 16#usize)
    (auth : List (Std.Array Std.U8 16#usize)) (hh : h < auth.length) :
    tree_path_step suppliedBackend (byteInts seed.val) (Int.ofNat layer) (Int.ofNat tree)
      (Int.ofNat kind) (Int.ofNat kp) (auth.map (fun v => byteInts v.val)) (Int.ofNat idx)
      (byteInts node.val) h =
      byteInts ((if (idx / 2^h) % 2 = 0 then
        th_pair_pure seed (pathAddress layer tree kind kp (h+1) (idx / 2^h / 2))
          (Equiv.pad16p node) (Equiv.pad16p auth[h])
      else th_pair_pure seed (pathAddress layer tree kind kp (h+1) (idx / 2^h / 2))
          (Equiv.pad16p auth[h]) (Equiv.pad16p node))).val := by
  have hs : List.getD (auth.map (fun v => byteInts v.val)) h (List.replicate 16 0) =
      byteInts auth[h].val := by simp [List.getD_eq_getElem?_getD, hh]
  unfold tree_path_step
  rw [hs]
  have hi : Int.ofNat idx / (2 : Int)^h = Int.ofNat (idx / 2^h) := by
    simp [Int.natCast_ediv, Int.natCast_pow]
  have hp : Int.ofNat (idx / 2^h) / 2 = Int.ofNat (idx / 2^h / 2) := by
    simp [Int.natCast_ediv]
  have hm : Int.ofNat (idx / 2^h) % 2 = Int.ofNat ((idx / 2^h) % 2) := by
    simp [Int.natCast_emod]
  rw [hi, hp, hm]
  have hz : Int.ofNat ((idx / 2^h) % 2) = 0 ↔ (idx / 2^h) % 2 = 0 := by
    change Int.ofNat _ = Int.ofNat 0 ↔ _
    exact ⟨Int.ofNat.inj, congrArg Int.ofNat⟩
  simp only [hz]
  split <;> rw [pair_pure_value, path_address_value]

theorem path_fold_value (seed : Std.Array Std.U8 32#usize)
    (layer tree kind kp idx : Nat) (auth : List (Std.Array Std.U8 16#usize))
    (n h : Nat) (node : Std.Array Std.U8 16#usize) (hb : h+n ≤ auth.length) :
    ((List.range' h n).foldl (fun current j =>
      tree_path_step suppliedBackend (byteInts seed.val) (Int.ofNat layer) (Int.ofNat tree)
        (Int.ofNat kind) (Int.ofNat kp) (auth.map (fun v => byteInts v.val))
        (Int.ofNat idx) current j) (byteInts node.val)) =
      byteInts (pathFold seed layer tree kind kp ((auth.drop h).take n)
        node (idx / 2^h) h).val := by
  induction n generalizing h node with
  | zero => simp [pathFold]
  | succ n ih =>
    have hh : h < auth.length := by omega
    have hd : (auth.drop h).take (n+1) = auth[h] :: (auth.drop (h+1)).take n := by
      rw [← List.cons_getElem_drop_succ (l := auth) (n := h) (h := hh)]
      rfl
    rw [List.range'_succ, List.foldl_cons, path_step_value _ _ _ _ _ _ _ _ _ hh,
      hd, pathFold]
    have hp : idx / 2^h / 2 = idx / 2^(h+1) := by
      rw [Nat.div_div_eq_div_mul, Nat.pow_succ]
    rw [hp]
    exact ih (h+1) _ (by omega)

theorem path_value (seed : Std.Array Std.U8 32#usize)
    (layer tree kind kp idx : Nat) (auth : List (Std.Array Std.U8 16#usize))
    (node : Std.Array Std.U8 16#usize) :
    byteInts (pathFold seed layer tree kind kp auth node idx 0).val =
      tree_path_value suppliedBackend (byteInts seed.val) (Int.ofNat layer) (Int.ofNat tree)
        (Int.ofNat kind) (Int.ofNat kp) (byteInts node.val) (Int.ofNat idx)
        (auth.map (fun v => byteInts v.val)) auth.length := by
  have h := path_fold_value seed layer tree kind kp idx auth auth.length 0 node (by omega)
  simpa [tree_path_value, List.range_eq_range'] using h.symm

theorem fors_fold_eq (seed : Std.Array Std.U8 32#usize) (ht tree : Std.U32)
    (auth : List (Std.Array Std.U8 16#usize)) (node : Std.Array Std.U8 16#usize)
    (idx h : Nat) :
    Equiv.forsRecoveryFold seed ht tree auth node idx h =
      pathFold seed 0 ht.val 3 tree.val auth node idx h := by
  induction auth generalizing node idx h with
  | nil => rfl
  | cons sibling rest ih =>
    simp only [Equiv.forsRecoveryFold, pathFold]
    exact ih _ _ _

theorem merkle_fold_eq (seed : Std.Array Std.U8 32#usize) (layer : Std.U32) (tree : Std.U64)
    (auth : List (Std.Array Std.U8 16#usize)) (node : Std.Array Std.U8 16#usize)
    (idx h : Nat) :
    Equiv.authFold seed layer tree auth node idx h =
      pathFold seed layer.val tree.val 2 0 auth node idx h := by
  induction auth generalizing node idx h with
  | nil => rfl
  | cons sibling rest ih =>
    simp only [Equiv.authFold, pathFold]
    exact ih _ _ _

/-- The actual helper hashes the supplied secret, then consumes eleven siblings.
    The target retains its complete u32 domain, including non-tree indices. -/
theorem extracted_fors_recover_value (seed : Std.Array Std.U8 32#usize)
    (ht tree target : Std.U32) (secret : Std.Array Std.U8 16#usize)
    (auth : Std.Array (Std.Array Std.U8 16#usize) 11#usize) :
    sphincs_c10.hypertree.reconstruct_fors_root seed ht tree target secret auth ⦃ r =>
      byteInts r.val = fors_recover_value suppliedBackend (byteInts seed.val)
        (Int.ofNat ht.val) (Int.ofNat tree.val) (Int.ofNat target.val)
        (byteInts secret.val) (auth.val.map (fun v => byteInts v.val)) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.fors_recovery_spec seed ht tree target secret auth
  rw [hr, fors_fold_eq, path_value, fors_leaf_pure_value]
  have hn : auth.val.length = 11 := by simpa using auth.property
  rw [hn]
  rfl

/-- Full-width address/index, the actual nine-level XMSS recovery helper. -/
theorem extracted_merkle_recover_value (seed : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (leaf : Std.Array Std.U8 16#usize)
    (index : Std.U32) (auth : Std.Array (Std.Array Std.U8 16#usize) 9#usize) :
    sphincs_c10.merkle.verify_auth_path seed layer tree leaf index auth ⦃ r =>
      byteInts r.val = merkle_recover_value suppliedBackend (byteInts seed.val)
        (Int.ofNat layer.val) (Int.ofNat tree.val) (byteInts leaf.val) (Int.ofNat index.val)
        (auth.val.map (fun v => byteInts v.val)) ⦄ := by
  let* ⟨r, hr⟩ ← Equiv.verify_auth_path_spec seed layer tree leaf index auth
  rw [hr, merkle_fold_eq, path_value]
  have hn : auth.val.length = 9 := by simpa using auth.property
  rw [hn]
  rfl

end Extracted.C10FunctionalTrees
