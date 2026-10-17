import C10Probability.TopTreeOpening
import C10Probability.WotsSignerExamples

/-! Finite reference and comparison witnesses. Coordinate, path length,
collision and zero-node conditions have concrete counterexamples when removed.
Populated caches do not establish an empty-cache success probability. -/
namespace C10Probability
noncomputable section

abbrev ReferencePathKey := ℕ × ℕ × ℕ × ℕ

def referencePair (height parent left right : ℕ) : ReferencePathKey := (height, parent, left, right)

def referenceTable (key : ReferencePathKey) : Option ℕ :=
  if key = referencePair 0 0 1 2 then some 7
  else if key = referencePair 0 1 3 4 then some 8
  else if key = referencePair 1 0 7 8 then some 9 else none

theorem tree_reference_table_collision_free : CollisionFree id referenceTable := by
  intro key other value reply hv hr same
  simp only [referenceTable] at hv hr
  split_ifs at hv hr <;> simp_all <;> omega

theorem tree_reference_four_leaf_certificate :
    RecordedTreeNode referenceTable (fun kp => some (kp + 1))
      (fun kp h l r => referencePair h (kp / 2 ^ (h + 1)) l r) id 2 4 9 := by
  have h := replay_tree_recorded referenceTable (fun kp => some (kp + 1))
    (fun kp h l r => referencePair h (kp / 2 ^ (h + 1)) l r) id
    (fun _ _ _ _ (_ : Unit) => ()) 4 0 [] () ([(9, 2)], ()) trivial rfl
  exact h.1

theorem tree_reference_all_four_reference_paths (index : ℕ) (bound : index < 4) :
    ∃ auth, auth.length = 2 ∧ replayPath referenceTable referencePair id 0 index (index + 1) auth = some 9 := by
  obtain ⟨value, auth, hl, hlen, hp⟩ := recorded_tree_reference referenceTable
    (fun kp => some (kp + 1)) referencePair id tree_reference_four_leaf_certificate 0 index rfl bound
  have he : index + 1 = value := by
    simpa only [Nat.mul_zero, Nat.zero_add] using Option.some.inj hl
  exact ⟨auth, hlen, by simpa only [Nat.mul_zero, Nat.zero_add, he] using hp⟩

theorem tree_reference_leftmost_reference : replayPath referenceTable referencePair id 0 0 1 [2, 8] = some 9 := by
  rfl

theorem tree_reference_rightmost_reference : replayPath referenceTable referencePair id 0 3 4 [3, 7] = some 9 := by
  rfl

theorem tree_reference_outside_tree_rejected : replayPath referenceTable referencePair id 0 4 5 [6, 8] = none := by
  rfl

theorem tree_reference_same_coordinate_binding (first second : ℕ) (auth auth' : List ℕ)
    (length : auth.length = auth'.length)
    (left : replayPath referenceTable referencePair id 0 0 first auth = some 9)
    (right : replayPath referenceTable referencePair id 0 0 second auth' = some 9) : first = second := by
  apply replay_path_leaf_eq referenceTable referencePair id _ 0 0 first second 9 auth auth' length left right
  intro h p l r l' r' a b ha hb equal
  have same := tree_reference_table_collision_free (referencePair h p l r) (referencePair h p l' r') a b ha hb equal
  simpa only [referencePair, Prod.mk.injEq, true_and] using same

theorem tree_reference_different_coordinates_same_root :
    replayPath referenceTable referencePair id 0 0 1 [2] = some 7 ∧
      replayPath referenceTable referencePair id 0 1 2 [1] = some 7 ∧ (1 : ℕ) ≠ 2 := by
  exact ⟨rfl, rfl, by decide⟩

theorem tree_reference_different_lengths_same_root :
    replayPath referenceTable referencePair id 0 0 7 [] = some 7 ∧
      replayPath referenceTable referencePair id 0 0 1 [2] = some 7 ∧ (7 : ℕ) ≠ 1 := by
  exact ⟨rfl, rfl, by decide⟩

theorem tree_reference_collision_allows_different_leaves :
    replayPath (fun _ : ReferencePathKey => some 7) referencePair id 0 0 1 [2] = some 7 ∧
      replayPath (fun _ : ReferencePathKey => some 7) referencePair id 0 0 2 [1] = some 7 ∧
      ¬ CollisionFree id (fun _ : ReferencePathKey => some 7) := by
  refine ⟨rfl, rfl, ?_⟩
  intro free
  have same := free (referencePair 0 0 1 2) (referencePair 0 0 2 1) 7 7 rfl rfl rfl
  simp [referencePair] at same

theorem tree_reference_missing_siblings_are_zero : pathSiblings ([1, 2] : List Randomizer) 0 4 0 = [1, 2, 0, 0] := by
  rfl

theorem tree_reference_excess_siblings_are_ignored : pathSiblings ([1, 2, 3] : List Randomizer) 0 2 0 = [1, 2] := by
  rfl

theorem tree_reference_zero_reference_leaf :
    replayProgram (fun _ : WotsQuery => some (0 : Digest))
      (wotsLeafProgram id (List.replicate 32 0) 1 0 0) = some 0 := by
  apply eval_program_replay digestDraw _ (fun _ => some 0) (0, fun _ => some 0)
  rw [wots_leaf_eval, wots_leaf_cached]
  have zero : randomizerOfDigest (0 : Digest) = 0 := by decide +kernel
  simp only [zero, PMF.mem_support_pure_iff]

theorem tree_reference_zero_reference_is_public_zero :
    PublicNodeZero (fun _ : ByteKey => some (0 : Digest)) := by
  refine ⟨[], 0, rfl, ?_⟩
  rw [node_zero_iff]
  decide +kernel

theorem tree_reference_rejected_wots_can_equal_zero_reference :
    replayProgram (fun _ : WotsQuery => some (0 : Digest))
      (wotsRecoveryUnderProgram Sum.inl (List.replicate 32 0) 1 0 0
        (nodeValueBytes 0) wotsZeroSigma 0) = some 0 ∧
      wotsAccept (wotsOfDigest (0 : Digest)) = false := by
  have rejected : wotsAccept (wotsOfDigest (0 : Digest)) = false := by decide +kernel
  refine ⟨?_, rejected⟩
  simp only [wotsRecoveryUnderProgram, replayProgram, Option.bind_some,
    wotsRecoveryAfter, rejected, Bool.false_eq_true, ↓reduceDIte, mapProgram]

end
end C10Probability
