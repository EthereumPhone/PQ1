import C10Probability.RForeignComposition
import C10Probability.WotsSigning

/-! The actual WOTS private seed derivations and public count/shuffle/chain
queries cannot populate a valid private R-context entry. -/
namespace C10Probability
noncomputable section

theorem wots_seed_chain_r_zero (seed : ByteKey) (layer tree kp index steps : ℕ) :
    SelectedBudget rPrivateQuery (wotsSeedChainProgram id seed layer tree kp index steps) 0 := by
  apply selected_zero_query rPrivateQuery _ _ (r_private_query_wots layer tree kp index)
  intro digest
  exact selected_zero_chain rPrivateQuery _ _ (fun _ _ => rfl) _ _ _

theorem wots_fill_r_zero (seed : ByteKey) (layer tree kp : ℕ)
    (steps : Fin 43 → ℕ) (order : List (Fin 43)) (sigma : WotsSigma) :
    SelectedBudget rPrivateQuery (wotsFillProgram id seed layer tree kp steps order sigma) 0 := by
  apply selected_zero_stateFold
  intro i state
  rw [wotsFillStep, selectedBudget_mapReturn]
  exact wots_seed_chain_r_zero seed layer tree kp i.val (steps i)

theorem wots_leaf_fill_r_zero (seed : ByteKey) (layer tree kp : ℕ) :
    SelectedBudget rPrivateQuery (wotsLeafFillProgram id seed layer tree kp) 0 := by
  rw [wotsLeafFillProgram, selectedBudget_cast]
  exact wots_fill_r_zero _ _ _ _ _ _ _

theorem wots_leaf_r_zero (seed : ByteKey) (layer tree kp : ℕ) :
    SelectedBudget rPrivateQuery (wotsLeafProgram id seed layer tree kp) 0 := by
  apply selected_zero_bind rPrivateQuery _ _ (wots_leaf_fill_r_zero seed layer tree kp)
  intro sigma
  exact selected_zero_query rPrivateQuery _ _ rfl (fun _ => trivial)

theorem wots_accepted_fill_r_zero (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (accepted : wotsAccept word = true) (order : WotsOrder) :
    SelectedBudget rPrivateQuery
      (wotsAcceptedFillProgram id seed layer tree kp word accepted order) 0 := by
  rw [wotsAcceptedFillProgram, selectedBudget_cast]
  exact wots_fill_r_zero _ _ _ _ _ _ _

theorem wots_sign_after_r_zero (seed : ByteKey) (layer tree kp : ℕ)
    (shuffle : ByteKey) (accepted : Option (ℕ × Digest)) :
    SelectedBudget rPrivateQuery (wotsSignAfterProgram id seed layer tree kp shuffle accepted) 0 := by
  cases accepted with
  | none => rw [wotsSignAfterProgram]; trivial
  | some value =>
    rcases value with ⟨count, digest⟩
    by_cases good : wotsAccept (wotsOfDigest digest) = true
    · rw [wotsSignAfterProgram, dif_pos good]
      apply selected_zero_bind rPrivateQuery
      · have budget := selectedBudget_map_none rPrivateQuery
          (Sum.inl : ByteKey → WotsQuery) (fun _ => rfl) (wotsShuffleProgram id shuffle)
        simpa only [wots_shuffle_map, Function.comp_def, id_eq] using budget
      · intro order
        rw [selectedBudget_mapReturn]
        exact wots_accepted_fill_r_zero _ _ _ _ _ good _
    · rw [wotsSignAfterProgram, dif_neg good]
      trivial

theorem wots_sign_r_zero (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    SelectedBudget rPrivateQuery (wotsSignProgram id seed layer tree kp message shuffle n bound) 0 := by
  rw [wotsSignProgram, selectedBudget_cast]
  exact selected_zero_bind rPrivateQuery _ _
    (selectedBudget_map_none rPrivateQuery _ (fun _ => rfl) _)
    (wots_sign_after_r_zero seed layer tree kp shuffle)

end
end C10Probability
