import C10Probability.TreeCertificate

/-! Finite nonempty examples of the actual stack replay and its certificates.
These populated-certificateTable computations make no fresh-oracle probability claim. -/
namespace C10Probability
noncomputable section

def certificatePairKey (kp height left right : ℕ) : ℕ := 100 * kp + 10 * height + 4 * left + right

def certificateTable : Memo ℕ ℕ := fun key =>
  if key = 106 then some 7 else if key = 316 then some 8 else if key = 346 then some 9 else none

def certificateLeafProgram (kp : ℕ) : QueryProgram ℕ ℕ ℕ 0 := .done (kp + 1)

def certificateRemember (kp height left right : ℕ) (log : List (ℕ × ℕ × ℕ × ℕ)) :=
  log ++ [(kp, height, left, right)]

theorem tree_certificate_two_leaf_replay :
    replayTree certificateTable (fun kp => some (kp + 1)) certificatePairKey id certificateRemember 2 0 [] [] =
      some ([(7, 1)], [(1, 0, 1, 2)]) := by
  rfl

theorem tree_certificate_three_leaf_replay :
    replayTree certificateTable (fun kp => some (kp + 1)) certificatePairKey id certificateRemember 3 0 [] [] =
      some ([(3, 0), (7, 1)], [(1, 0, 1, 2)]) := by
  rfl

theorem tree_certificate_four_leaf_compiled_replay :
    (replayProgram certificateTable (treeProgram 0 certificateLeafProgram certificatePairKey id certificateRemember 4 0 [] PUnit.unit [])).map
        (eraseTreeState (runShape 4 [])) =
      some ([(9, 2)], [(1, 0, 1, 2), (3, 0, 3, 4), (3, 1, 7, 8)]) := by
  rw [replay_tree_program]
  rfl

theorem tree_certificate_four_leaf_certificate :
    RecordedTreeNode certificateTable (fun kp => some (kp + 1)) certificatePairKey id 2 4 9 := by
  have h := replay_tree_recorded certificateTable (fun kp => some (kp + 1)) certificatePairKey id certificateRemember
    4 0 [] [] ([(9, 2)], [(1, 0, 1, 2), (3, 0, 3, 4), (3, 1, 7, 8)]) trivial rfl
  exact h.1

theorem tree_certificate_missing_parent_rejected :
    replayTree (fun key => if key = 346 then none else certificateTable key)
      (fun kp => some (kp + 1)) certificatePairKey id certificateRemember 4 0 [] [] = none := by
  rfl

theorem tree_certificate_reversed_children_rejected :
    replayTree certificateTable (fun kp => some (kp + 1))
      (fun kp h left right => certificatePairKey kp h right left) id certificateRemember 2 0 [] [] = none := by
  rfl

end
end C10Probability
