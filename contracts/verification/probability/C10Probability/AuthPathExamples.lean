import C10Probability.ReturnedForsSigning

/-! An asymmetric four-leaf cache distinguishes both children and both levels.
These are finite populated-cache witnesses, not empty-cache probability claims. -/
namespace C10Probability
noncomputable section

abbrev AuthExampleKey := ℕ × ℕ × Randomizer × Randomizer

def authExamplePair (height parent : ℕ) (left right : Randomizer) : AuthExampleKey :=
  (height, parent, left, right)

def authExampleInput (kp height : ℕ) (left right : Randomizer) : AuthExampleKey :=
  authExamplePair height (kp / 2 ^ (height + 1)) left right

def authExampleTable : Memo AuthExampleKey Randomizer := fun key =>
  some ⟨(10 * key.1 + 100 * key.2.1 + 3 * key.2.2.1.val + key.2.2.2.val) % 2 ^ 128,
    Nat.mod_lt _ (by decide)⟩

def authExampleLeaf (kp : ℕ) : Option Randomizer :=
  some ⟨(kp + 1) % 2 ^ 128, Nat.mod_lt _ (by decide)⟩

theorem four_leaf_fors_returned_paths :
    (List.range 4).map (fun target => replayTree authExampleTable authExampleLeaf
      authExampleInput id (forsRemember target) 4 0 [] [0, 0]) =
    [some ([(138, 2)], [2, 113]), some ([(138, 2)], [1, 113]),
      some ([(138, 2)], [4, 5]), some ([(138, 2)], [3, 5])] := by decide +kernel

theorem four_leaf_merkle_returned_paths :
    (List.range 4).map (fun target => (replayTree authExampleTable authExampleLeaf
      authExampleInput id (authRemember target) 4 0 [] ⟨[0, 0], [false, false]⟩).map
      (fun out => (out.1, out.2.nodes, out.2.kept))) =
    [some ([(138, 2)], [2, 113], [true, true]), some ([(138, 2)], [1, 113], [true, true]),
      some ([(138, 2)], [4, 5], [true, true]), some ([(138, 2)], [3, 5], [true, true])] := by decide +kernel

theorem four_leaf_returned_recovery_vector :
    ([([2, 113], 1, 0), ([1, 113], 2, 1), ([4, 5], 3, 2), ([3, 5], 4, 3)] :
      List (List Randomizer × Randomizer × ℕ)).map (fun entry =>
        replayPath authExampleTable authExamplePair id 0 entry.2.2 entry.2.1 entry.1) =
      [some 138, some 138, some 138, some 138] := by decide +kernel

theorem four_leaf_swapped_path_fails :
    replayPath authExampleTable authExamplePair id 0 2 3 [5, 4] ≠ some 138 := by decide +kernel

theorem initially_kept_path_fails :
    replayTree authExampleTable authExampleLeaf authExampleInput id (authRemember 2)
      4 0 [] ⟨[0, 0], [true, true]⟩ = some ([(138, 2)], ⟨[0, 0], [true, true]⟩) ∧
    replayPath authExampleTable authExamplePair id 0 2 3 [0, 0] ≠ some 138 := by decide +kernel

theorem short_initial_path_fails :
    replayTree authExampleTable authExampleLeaf authExampleInput id (forsRemember 2)
      4 0 [] [] = some ([(138, 2)], []) ∧
    replayPath authExampleTable authExamplePair id 0 2 3 [] ≠ some 138 := by decide +kernel

theorem out_of_range_target_fails :
    replayTree authExampleTable authExampleLeaf authExampleInput id (forsRemember 4)
      4 0 [] [0, 0] = some ([(138, 2)], [0, 0]) ∧
    replayPath authExampleTable authExamplePair id 0 4 5 [0, 0] ≠ some 138 := by decide +kernel

theorem unaligned_merge_path_fails :
    replayMerge authExampleTable authExampleInput id (forsRemember 2) 2 [(2, 0)] 0 3 [0] =
      some ([(109, 1)], [3]) ∧
    replayPath authExampleTable authExamplePair id 0 2 3 [3] ≠ some 109 := by decide +kernel

theorem four_leaf_collected_certificate :
    CollectedTreeNode authExampleTable authExampleLeaf authExampleInput id 2 [4, 5] 2 4 138 := by
  have cert := replay_tree_collected authExampleTable authExampleLeaf authExampleInput id
    2 2 id (fun auth => auth.length = 2) (forsRemember 2)
    (fors_remember_auth_law authExampleTable authExampleLeaf authExampleInput id 2 2)
    4 0 [] [0, 0] ([(138, 2)], [4, 5]) rfl (by decide +kernel) trivial (by decide +kernel)
  exact cert.2.1

theorem four_leaf_collected_recovery :
    ∃ leaf, authExampleLeaf 2 = some leaf ∧
      replayPath authExampleTable authExamplePair id 0 2 leaf [4, 5] = some 138 := by
  exact collected_complete_path authExampleTable authExampleLeaf authExamplePair id
    2 2 [4, 5] 138 four_leaf_collected_certificate rfl (by decide)

end
end C10Probability
