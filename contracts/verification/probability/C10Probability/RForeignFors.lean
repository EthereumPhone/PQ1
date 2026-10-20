import C10Probability.RForeignComposition
import C10Probability.ForestSign

/-! Zero private-R budgets for the real FORS tree and forest signing callers,
including shuffle, recovery, the final transmitted root and compression. -/
namespace C10Probability
noncomputable section

variable {S : Type*}

attribute [local irreducible] treeProgram

theorem fors_leaf_r_zero (seed : ByteKey) (ht tree leaf : ℕ) :
    SelectedBudget rPrivateQuery (forsLeafProgram id seed ht tree leaf) 0 := by
  apply selected_zero_query rPrivateQuery _ _ (r_private_query_fors ht tree leaf)
  intro secret
  exact selected_zero_query rPrivateQuery _ _ rfl (fun _ => trivial)

theorem fors_tree_state_r_zero (seed : ByteKey) (ht tree : ℕ)
    (remember : ℕ → ℕ → Randomizer → Randomizer → S → S) (initial : S) :
    SelectedBudget rPrivateQuery (forsTreeStateProgram id seed ht tree remember initial) 0 := by
  rw [forsTreeStateProgram, selectedBudget_cast, selectedBudget_mapReturn]
  have step (count : ℕ) := selected_zero_tree
    (K := WotsQuery) (α := Digest) (N := Randomizer) (S := S)
    rPrivateQuery 2 (forsLeafProgram id seed ht tree) (fors_leaf_r_zero seed ht tree)
    (fun leaf h l r => id (.inl (forsTreePairInput seed ht tree leaf h l r)))
    randomizerOfDigest (fun _ _ _ _ => rfl) remember count 0 [] PUnit.unit initial
  exact step 2048

theorem fors_tree_r_zero (seed : ByteKey) (ht tree target : ℕ) :
    SelectedBudget rPrivateQuery (forsTreeProgram id seed ht tree target) 0 := by
  rw [forsTreeProgram, selectedBudget_mapReturn]
  exact fors_tree_state_r_zero _ _ _ _ _

theorem fors_root_r_zero (seed : ByteKey) (ht tree : ℕ) :
    SelectedBudget rPrivateQuery (forsRootProgram id seed ht tree) 0 := by
  rw [forsRootProgram, selectedBudget_mapReturn]
  exact fors_tree_r_zero _ _ _ _

theorem fors_sign_r_zero (seed : ByteKey) (ht tree target : ℕ) :
    SelectedBudget rPrivateQuery (forsSignProgram id seed ht tree target) 0 := by
  apply selected_zero_query rPrivateQuery _ _ (r_private_query_fors ht tree target)
  intro secret
  rw [selectedBudget_mapReturn]
  exact fors_tree_r_zero _ _ _ _

theorem forest_one_r_zero (seed : ByteKey) (ht tree target : ℕ) :
    SelectedBudget rPrivateQuery (forestOneProgram id seed ht tree target) 0 := by
  apply selected_zero_bind rPrivateQuery _ _ (fors_sign_r_zero seed ht tree target)
  intro sig
  rw [selectedBudget_mapReturn]
  have budget := selectedBudget_map_none rPrivateQuery
    (Sum.inl : ByteKey → WotsQuery) (fun _ => rfl)
    (forsRecoverProgram id seed ht tree target sig.1 sig.2)
  simpa only [fors_recover_map, Function.comp_def, id_eq] using budget

theorem forest_fill_r_zero (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : List (Fin 12)) (state : ForestState) :
    SelectedBudget rPrivateQuery (forestFillProgram id seed ht digest order state) 0 := by
  apply selected_zero_stateFold
  intro tree state
  rw [forestFillStep, selectedBudget_mapReturn]
  exact forest_one_r_zero _ _ _ _

theorem forest_ordered_r_zero (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (order : ForestOrder) :
    SelectedBudget rPrivateQuery (forestOrderedProgram id seed ht digest order) 0 := by
  rw [forestOrderedProgram, selectedBudget_cast]
  exact forest_fill_r_zero _ _ _ _ _

theorem forest_finish_r_zero (seed : ByteKey) (ht : ℕ) (state : ForestState) :
    SelectedBudget rPrivateQuery (forestFinishProgram id seed ht state) 0 := by
  apply selected_zero_bind rPrivateQuery _ _ (fors_root_r_zero seed ht 12)
  intro last
  exact selected_zero_query rPrivateQuery _ _ rfl (fun _ =>
    selected_zero_query rPrivateQuery _ _ rfl (fun _ => trivial))

theorem forest_sign_r_zero (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) :
    SelectedBudget rPrivateQuery (forestSignProgram id seed ht digest shuffle) 0 := by
  rw [forestSignProgram]
  apply selected_zero_bind rPrivateQuery
  · have budget := selectedBudget_map_none rPrivateQuery
      (Sum.inl : ByteKey → WotsQuery) (fun _ => rfl) (forestShuffleProgram id shuffle)
    simpa only [forest_shuffle_map, Function.comp_def, id_eq] using budget
  · intro order
    exact selected_zero_bind rPrivateQuery _ _ (forest_ordered_r_zero seed ht digest order)
      (forest_finish_r_zero seed ht)

end
end C10Probability
