import C10Probability.MerkleCharges
import C10Probability.WotsSignerExamples

/-! Independent finite geometry, byte, sibling-selection, query-order and
shared-cache witnesses. Typed controls exercise these unchanged consumers. -/
namespace C10Probability
noncomputable section

set_option maxRecDepth 4096

theorem tree_shape_frontier :
    runShape 3 [] = [0,1] ∧ runShape 7 [] = [0,1,2] ∧
    (mergeShape 0 [0,1,2]) = ⟨3,[],3⟩ ∧ (mergeShape 0 [1]) = ⟨0,[1],0⟩ := by
  decide +kernel

theorem merkle_pair_byte_vector :
    merklePairInput [] 258 (2 ^ 40 + 3) 7 772 1 2 =
      [0,0,1,2,0,0,1,0,0,0,0,3,0,0,0,2] ++ List.replicate 11 0 ++
      [8,0,0,3,4] ++ List.replicate 15 0 ++ [1] ++ List.replicate 31 0 ++
      [2] ++ List.replicate 16 0 := by
  decide +kernel

theorem tree_pair_parent_vector :
    (treePairInput [] 0 0 511 3 1 2).take 32 =
      List.replicate 15 0 ++ [2] ++ List.replicate 11 0 ++ [4,0,0,0,31] := by
  decide +kernel

theorem sibling_index_vector :
    (List.range 8).map siblingIndex = [1,0,3,2,5,4,7,6] := by decide +kernel

theorem auth_remember_left_vector :
    authRemember 1 1 0 11 22 emptyAuthKeep =
      ⟨[11] ++ List.replicate 8 0, [true] ++ List.replicate 8 false⟩ := by decide +kernel

theorem auth_remember_right_vector :
    authRemember 0 1 0 11 22 emptyAuthKeep =
      ⟨[22] ++ List.replicate 8 0, [true] ++ List.replicate 8 false⟩ := by decide +kernel

theorem auth_remember_high_vector :
    authRemember 0 511 8 11 22 emptyAuthKeep =
      ⟨List.replicate 8 0 ++ [22], List.replicate 8 false ++ [true]⟩ := by decide +kernel

theorem auth_remember_irrelevant_vector :
    authRemember 4 1 0 11 22 emptyAuthKeep = emptyAuthKeep := by decide +kernel

theorem auth_remember_once_vector :
    authRemember 1 1 0 33 44 (authRemember 1 1 0 11 22 emptyAuthKeep) =
      ⟨[11] ++ List.replicate 8 0, [true] ++ List.replicate 8 false⟩ := by decide +kernel

theorem recovery_even_vector :
    recoveryInput [] 1 2 1 6 [3,4,5] 9 = merklePairInput [] 1 2 1 3 9 4 := by
  decide +kernel

theorem recovery_odd_vector :
    recoveryInput [] 1 2 1 7 [3,4,5] 9 = merklePairInput [] 1 2 1 3 4 9 := by
  decide +kernel

theorem recovery_default_vector :
    recoveryInput [] 1 2 2 6 [3] 9 = merklePairInput [] 1 2 2 3 9 0 := by
  decide +kernel

theorem tree_root_default_vector : treeRoot [] = 0 := by rfl

def treeExampleInput (_ _ left right : ℕ) : ℕ := left * 10 + right

theorem merge_two_levels_cached :
    mergeLoop (PMF.pure 0) treeExampleInput id
      (fun _ h l r (state : List ℕ) => state ++ [l,r,h]) 3 [(2,0),(3,1)] 0 4 []
      (fun key => some key) =
      PMF.pure (([(54,2)],[2,4,0,3,24,1]), fun key => some key) := by
  simp [mergeLoop, treeExampleInput, memoQuery, PMF.pure_bind]

theorem merge_stops_at_different_height :
    mergeLoop (PMF.pure 0) treeExampleInput id
      (fun _ _ _ _ (_ : Unit) => ()) 0 [(2,1)] 0 4 () (fun _ => none) =
      PMF.pure (([(4,0),(2,1)],()), fun _ => none) := by
  simp [mergeLoop]

theorem merge_accumulated_cache :
    mergeLoop (PMF.pure (8 : ℕ)) (fun (_ : ℕ) h (_ _ : ℕ) => decide (h = 1)) id
      (fun _ _ _ _ (_ : Unit) => ()) 3 [(2,0),(3,1)] 0 4 () (fun _ => none) =
      PMF.pure (([(8,2)],()), Function.update
        (Function.update (fun _ => none) false (some 8)) true (some 8)) := by
  simp [mergeLoop, memoQuery, PMF.pure_map, PMF.pure_bind]

theorem tree_four_leaves_cached :
    treeLoop (PMF.pure 0) (fun kp table => PMF.pure (kp + 1, table)) treeExampleInput id
      (fun _ _ _ _ (_ : Unit) => ()) 4 0 [] () (fun key => some key) =
      PMF.pure (([(154,2)],()), fun key => some key) := by
  simp [treeLoop, mergeLoop, treeExampleInput, memoQuery, PMF.pure_bind]

theorem tree_four_leaves_query_order :
    (traceProgram (PMF.pure 0)
      (treeProgram 0 (fun kp => .done (kp + 1)) treeExampleInput id
        (fun _ _ _ _ (_ : Unit) => ()) 4 0 [] PUnit.unit ()) (fun key => some key)).map
      (fun out => out.queries) = PMF.pure [12,34,154] := by
  simp [treeProgram, mergeProgram, nextShape, mergeShape, mergedShape,
    castTreeProgram, castProgram, bindProgram,
    reserveProgram, treeExampleInput, traceProgram, memoQuery, PMF.pure_bind, PMF.pure_map]

theorem merkle_recovery_query_order :
    (traceProgram digestDraw (merkleRecoverProgram id [] 1 2 2 511 [3,4,5,6,7,8,9,10,11])
      (fun _ => some (2 ^ 128))).map (fun out => out.queries) = PMF.pure
      [merklePairInput [] 1 2 0 255 3 2,
       merklePairInput [] 1 2 1 127 4 1,
       merklePairInput [] 1 2 2 63 5 1,
       merklePairInput [] 1 2 3 31 6 1,
       merklePairInput [] 1 2 4 15 7 1,
       merklePairInput [] 1 2 5 7 8 1,
       merklePairInput [] 1 2 6 3 9 1,
       merklePairInput [] 1 2 7 1 10 1,
       merklePairInput [] 1 2 8 0 11 1] := by
  have hp : randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel
  simp [merkleRecoverProgram, recoveryProgram, traceProgram, memoQuery,
    PMF.pure_bind, PMF.pure_map, hp, recoveryInput]

theorem recovery_loop_cached {K : Type*} [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (layer tree : ℕ) (auth : List Randomizer) (steps height index : ℕ)
    (current : Randomizer) (digest : Digest) :
    recoveryLoop encode seed layer tree auth (steps + 1) height index current
      (fun _ => some digest) = PMF.pure (randomizerOfDigest digest, fun _ => some digest) := by
  induction steps generalizing height index current with
  | zero => simp [recoveryLoop, memoQuery, PMF.pure_bind]
  | succ steps ih =>
    rw [recoveryLoop, memoQuery, PMF.pure_bind]
    exact ih (height + 1) (index / 2) (randomizerOfDigest digest)

theorem merkle_recover_cached {K : Type*} [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (layer tree : ℕ) (auth : List Randomizer) (index : ℕ)
    (current : Randomizer) (digest : Digest) :
    merkleRecover encode (fun _ => some digest) seed layer tree current index auth =
      PMF.pure (randomizerOfDigest digest, fun _ => some digest) := by
  exact recovery_loop_cached _ _ _ _ _ 8 _ _ _ _

theorem recovery_one_fresh_cache :
    recoveryLoop (fun _ => false) [] 1 2 [3] 1 0 0 4 (fun _ => none) =
      digestDraw.map (fun digest => (randomizerOfDigest digest,
        Function.update (fun _ => none) false (some digest))) := by
  simp only [recoveryLoop, memoQuery, PMF.bind_map]
  rfl

theorem recovery_one_fresh_populated :
    (recoveryLoop (fun _ => false) [] 1 2 [3] 1 0 0 4 (fun _ => none)).map
      (fun out => (out.2 false).isSome) = PMF.pure true := by
  simp [recoveryLoop, memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map]

theorem recovery_nine_heights :
    merkleRecover (fun key => (key[27]?).getD 0)
      (fun height => some (⟨height.val * 2 ^ 128,
        by have := height.isLt; omega⟩ : Digest))
      [] 1 2 4 511 [3,4,5,6,7,8,9,10,11] =
      PMF.pure (9, fun height => some (⟨height.val * 2 ^ 128,
        by have := height.isLt; omega⟩ : Digest)) := by
  have hp : randomizerOfDigest (3062541302288446171170371466885913903104 : Digest) = 9 := by decide +kernel
  simp [merkleRecover, recoveryLoop, memoQuery, PMF.pure_bind,
    recoveryInput, merklePairInput, c10Address, beBytes, nodeBlock, hp]

end
end C10Probability
