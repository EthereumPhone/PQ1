import C10Probability.RForeignTree
import C10Probability.RForeignFors
import C10Probability.C10Sign

/-! Every query after the R search in complete C10 signing is foreign to valid
private R contexts. Both WOTS failure branches and their retained caches are
covered; this result does not bound WOTS exhaustion. -/
namespace C10Probability
noncomputable section

theorem layer_sign_after_r_zero (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (auth : List Randomizer) (signed : WotsSignature) :
    SelectedBudget rPrivateQuery
      (layerSignAfterProgram id seed layer tree leaf message auth signed) 0 := by
  cases signed with
  | none => trivial
  | some value =>
    rcases value with ⟨sigma, count⟩
    rw [layerSignAfterProgram, selectedBudget_mapReturn]
    have budget := selectedBudget_map_none rPrivateQuery
      (Sum.inl : ByteKey → WotsQuery) (fun _ => rfl)
      (layerRecoverProgram id seed layer tree leaf message ⟨sigma, count, auth⟩)
    simpa only [layer_recover_map, Function.comp_def, id_eq] using budget

theorem layer_sign_r_zero (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    SelectedBudget rPrivateQuery
      (layerSignProgram id seed layer tree leaf message shuffle n bound) 0 := by
  rw [layerSignProgram, selectedBudget_cast]
  apply selected_zero_bind rPrivateQuery _ _ (merkle_build_r_zero seed layer tree leaf)
  intro built
  apply selected_zero_bind rPrivateQuery
  · have budget := selectedBudget_map_none rPrivateQuery
      (Sum.inl : ByteKey → WotsQuery) (fun _ => rfl)
      (shuffleDeriveProgram id shuffle (layerShuffleLabel layer))
    simpa only [shuffle_derive_map, Function.comp_def, id_eq] using budget
  · intro subseed
    exact selected_zero_bind rPrivateQuery _ _
      (wots_sign_r_zero seed layer tree leaf (nodeValueBytes message) subseed n bound)
      (layer_sign_after_r_zero seed layer tree leaf message built.1)

theorem hypertree_sign_r_zero (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (steps layer index : ℕ) (current : Randomizer) (signatures : List LayerSignature) :
    SelectedBudget rPrivateQuery
      (hypertreeSignProgram id seed shuffle n bound steps layer index current signatures) 0 := by
  induction steps generalizing layer index current signatures with
  | zero => rw [hypertreeSignProgram]; trivial
  | succ steps ih =>
    rw [hypertreeSignProgram, selectedBudget_cast]
    apply selected_zero_bind rPrivateQuery _ _ (layer_sign_r_zero _ _ _ _ _ _ _ _)
    intro signed
    cases signed with
    | none => trivial
    | some value => exact ih _ _ _ _

theorem c10_finish_r_zero (seed : ByteKey) (randomizer : Randomizer) (digest : Digest)
    (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32) :
    SelectedBudget rPrivateQuery (c10FinishProgram id seed randomizer digest shuffle n bound) 0 := by
  rw [c10FinishProgram, selectedBudget_cast]
  apply selected_zero_bind rPrivateQuery _ _ (forest_sign_r_zero _ _ _ _)
  intro forest
  rw [selectedBudget_mapReturn]
  exact hypertree_sign_r_zero _ _ _ _ _ _ _ _ _

theorem c10_sign_after_r_zero (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (found : Option (ℕ × Randomizer × Digest)) :
    SelectedBudget rPrivateQuery (c10SignAfterProgram id seed shuffle n bound found) 0 := by
  cases found with
  | none => trivial
  | some value => exact c10_finish_r_zero _ _ _ _ _ _

theorem c10_sign_after_r_history (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (found : Option (ℕ × Randomizer × Digest)) (contexts : Finset RContext)
    (table : Memo WotsQuery Digest) (history : RContextHistory contexts table)
    (out : Option C10Signature × Memo WotsQuery Digest)
    (supported : out ∈ (c10SignAfter id table seed shuffle n bound found).support) :
    RContextHistory contexts out.2 := by
  apply r_context_history_foreign (c10SignAfterProgram id seed shuffle n bound found)
    (c10_sign_after_r_zero seed shuffle n bound found) contexts table history out
  rwa [c10_sign_after_eval]

end
end C10Probability
