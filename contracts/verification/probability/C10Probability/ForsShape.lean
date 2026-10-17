import C10Probability.TreeAccess

/-! Derive FORS tree costs from the existing executed stack schedule. No merge
count, final shape or authentication-height bound is supplied as a premise. -/
namespace C10Probability

theorem fors_tree_shape : runShape 2048 [] = [11] := by
  set_option maxRecDepth 80000 in decide +kernel

theorem fors_tree_merge_calls : shapeCalls 2048 [] = 2047 := by
  have h := shape_calls_accounting 2048 []
  rw [fors_tree_shape] at h
  simp only [List.length_cons, List.length_nil] at h
  omega

theorem fors_tree_merge_height_bound : shapeHeightBound 11 2048 [] := by
  set_option maxRecDepth 80000 in decide +kernel

theorem fors_tree_auth_indices : treeAccessBound 11 2048 [] :=
  tree_access_bound 11 2048 [] fors_tree_merge_height_bound

theorem fors_tree_raw_calls : treeCalls 2 2048 [] = 6143 := by
  rw [treeCalls, fors_tree_merge_calls]

theorem fors_tree_public_calls : treeCalls 1 2048 [] = 4095 := by
  rw [treeCalls, fors_tree_merge_calls]

end C10Probability
