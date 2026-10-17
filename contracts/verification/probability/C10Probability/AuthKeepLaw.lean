import C10Probability.AuthCollect

/-! A true kept flag must certify the corresponding stored node. This invariant
is derived from the all-false initial flags and is preserved by actual writes. -/
namespace C10Probability
noncomputable section

variable {K α : Type*}

def AuthKeepValid (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target bound : ℕ) (state : AuthKeep) : Prop :=
  state.nodes.length = bound ∧ state.kept.length = bound ∧
    ∀ j, (state.kept[j]?).getD false = true →
      RecordedAuthSlot table leaf input project target state.nodes j

theorem initial_auth_keep_valid (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target : ℕ) : AuthKeepValid table leaf input project target 9 emptyAuthKeep := by
  refine ⟨by simp [emptyAuthKeep], by simp [emptyAuthKeep], ?_⟩
  intro j hj
  simp only [emptyAuthKeep, List.getElem?_replicate] at hj
  split at hj <;> simp_all

theorem auth_keep_write_valid (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target bound height : ℕ) (value : Randomizer) (state : AuthKeep)
    (valid : AuthKeepValid table leaf input project target bound state)
    (inRange : height < bound)
    (node : RecordedTreeNode table leaf input project height
      ((siblingIndex (target / 2 ^ height) + 1) * 2 ^ height) value) :
    AuthKeepValid table leaf input project target bound (writeAuthKeep state height value) ∧
    (∀ j, RecordedAuthSlot table leaf input project target state.nodes j →
      RecordedAuthSlot table leaf input project target (writeAuthKeep state height value).nodes j) ∧
    RecordedAuthSlot table leaf input project target (writeAuthKeep state height value).nodes height := by
  have cert := recorded_auth_set table leaf input project target state.nodes height value
    (by rw [valid.1]; exact inRange) node
  refine ⟨⟨by simpa [writeAuthKeep] using valid.1,
    by simpa [writeAuthKeep] using valid.2.1, ?_⟩, cert.2, cert.1⟩
  intro j hj
  by_cases he : height = j
  · subst j; exact cert.1
  · apply cert.2 j
    apply valid.2.2 j
    simpa only [writeAuthKeep, List.getElem?_set_ne he] using hj

theorem merkle_remember_auth_law (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target bound : ℕ) :
    RememberAuthLaw table leaf input project target bound AuthKeep.nodes
      (AuthKeepValid table leaf input project target bound) (authRemember target) := by
  intro kp height left right state valid inRange aligned hl hr
  by_cases hk : (state.kept[height]?).getD false = true
  · rw [auth_remember_kept target kp height left right state hk]
    exact ⟨valid, fun _ h => h, fun _ _ => valid.2.2 height hk⟩
  · simp only [authRemember, hk, auth_pair_start]
    by_cases sl : 2 * (kp / 2 ^ (height + 1)) = siblingIndex (target / 2 ^ height)
    · simp only [sl, ↓reduceIte]
      have cert := auth_keep_write_valid table leaf input project target bound height left state
        valid inRange (by simpa only [merge_sibling_left_edge target kp height aligned sl] using hl)
      exact ⟨cert.1, cert.2.1, fun _ _ => cert.2.2⟩
    · by_cases sr : 2 * (kp / 2 ^ (height + 1)) + 1 = siblingIndex (target / 2 ^ height)
      · simp only [sl, sr, ↓reduceIte]
        have cert := auth_keep_write_valid table leaf input project target bound height right state
          valid inRange (by simpa only [merge_sibling_right_edge target kp height aligned sr] using hr)
        exact ⟨cert.1, cert.2.1, fun _ _ => cert.2.2⟩
      · simp only [sl, sr, ↓reduceIte]
        refine ⟨valid, fun _ h => h, ?_⟩
        intro lower upper
        rcases merge_sibling_selected target kp height aligned lower upper with h | h
        · exact (sl h).elim
        · exact (sr h).elim

end
end C10Probability
