import C10Probability.AuthGeometry
import C10Probability.AuthCertificate

/-! Every actual write stores the certified sibling at its selected coordinate.
Repeated writes preserve certification without any collision assumption. -/
namespace C10Probability
noncomputable section

variable {K α : Type*}

theorem merge_sibling_selected (target kp height : ℕ)
    (aligned : (kp + 1) % 2 ^ (height + 1) = 0)
    (lower : kp + 1 - 2 ^ (height + 1) ≤ target) (upper : target < kp + 1) :
    2 * (kp / 2 ^ (height + 1)) = siblingIndex (target / 2 ^ height) ∨
      2 * (kp / 2 ^ (height + 1)) + 1 = siblingIndex (target / 2 ^ height) := by
  have edge := aligned_merge_edge kp height aligned
  have hp : 0 < 2 ^ (height + 1) := pow_pos (by decide) _
  have base : kp + 1 - 2 ^ (height + 1) =
      2 ^ (height + 1) * (kp / 2 ^ (height + 1)) := by
    rw [edge, Nat.mul_add, Nat.mul_one, Nat.add_sub_cancel]
  have quotient : target / 2 ^ (height + 1) = kp / 2 ^ (height + 1) := by
    apply Nat.div_eq_of_lt_le
    · rw [base] at lower
      simpa only [Nat.mul_comm] using lower
    · rw [edge] at upper
      simpa only [Nat.mul_comm] using upper
  have halves : (target / 2 ^ height) / 2 = kp / 2 ^ (height + 1) := by
    simpa only [Nat.div_div_eq_div_mul, ← pow_succ] using quotient
  have hs := sibling_parent (target / 2 ^ height)
  omega

theorem merge_sibling_left_edge (target kp height : ℕ)
    (aligned : (kp + 1) % 2 ^ (height + 1) = 0)
    (selected : 2 * (kp / 2 ^ (height + 1)) = siblingIndex (target / 2 ^ height)) :
    (siblingIndex (target / 2 ^ height) + 1) * 2 ^ height = kp + 1 - 2 ^ height := by
  have edge := aligned_merge_edge kp height aligned
  rw [← selected]
  have he : kp + 1 = (2 * (kp / 2 ^ (height + 1)) + 1) * 2 ^ height + 2 ^ height := by
    rw [edge, pow_succ]; ring
  omega

theorem merge_sibling_right_edge (target kp height : ℕ)
    (aligned : (kp + 1) % 2 ^ (height + 1) = 0)
    (selected : 2 * (kp / 2 ^ (height + 1)) + 1 = siblingIndex (target / 2 ^ height)) :
    (siblingIndex (target / 2 ^ height) + 1) * 2 ^ height = kp + 1 := by
  rw [← selected, aligned_merge_edge kp height aligned, pow_succ]
  ring

theorem recorded_auth_set (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target : ℕ) (auth : List Randomizer) (height : ℕ) (value : Randomizer)
    (bound : height < auth.length)
    (node : RecordedTreeNode table leaf input project height
      ((siblingIndex (target / 2 ^ height) + 1) * 2 ^ height) value) :
    RecordedAuthSlot table leaf input project target (auth.set height value) height ∧
    (∀ j, RecordedAuthSlot table leaf input project target auth j →
      RecordedAuthSlot table leaf input project target (auth.set height value) j) := by
  have here : RecordedAuthSlot table leaf input project target (auth.set height value) height :=
    ⟨value, List.getElem?_set_self bound, node⟩
  refine ⟨here, ?_⟩
  intro j hj
  by_cases he : height = j
  · subst j; exact here
  · obtain ⟨old, ho, hn⟩ := hj
    exact ⟨old, by simpa only [List.getElem?_set_ne he] using ho, hn⟩

theorem collect_auth_certified (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target kp height : ℕ) (left right : Randomizer) (auth : List Randomizer)
    (bound : height < auth.length)
    (aligned : (kp + 1) % 2 ^ (height + 1) = 0)
    (hl : RecordedTreeNode table leaf input project height (kp + 1 - 2 ^ height) left)
    (hr : RecordedTreeNode table leaf input project height (kp + 1) right) :
    (collectAuth target kp height left right auth).length = auth.length ∧
    (∀ j, RecordedAuthSlot table leaf input project target auth j →
      RecordedAuthSlot table leaf input project target (collectAuth target kp height left right auth) j) ∧
    (kp + 1 - 2 ^ (height + 1) ≤ target → target < kp + 1 →
      RecordedAuthSlot table leaf input project target (collectAuth target kp height left right auth) height) := by
  by_cases sl : 2 * (kp / 2 ^ (height + 1)) = siblingIndex (target / 2 ^ height)
  · simp only [collectAuth, sl, ↓reduceIte, List.length_set]
    have cert := recorded_auth_set table leaf input project target auth height left bound
      (by simpa only [merge_sibling_left_edge target kp height aligned sl] using hl)
    exact ⟨True.intro, cert.2, fun _ _ => cert.1⟩
  · by_cases sr : 2 * (kp / 2 ^ (height + 1)) + 1 = siblingIndex (target / 2 ^ height)
    · simp only [collectAuth, sl, sr, ↓reduceIte, List.length_set]
      have cert := recorded_auth_set table leaf input project target auth height right bound
        (by simpa only [merge_sibling_right_edge target kp height aligned sr] using hr)
      exact ⟨True.intro, cert.2, fun _ _ => cert.1⟩
    · simp only [collectAuth, sl, sr, ↓reduceIte]
      refine ⟨True.intro, fun _ h => h, ?_⟩
      intro lower upper
      rcases merge_sibling_selected target kp height aligned lower upper with h | h
      · exact (sl h).elim
      · exact (sr h).elim

theorem fors_remember_auth_law (table : Memo K α) (leaf : ℕ → Option Randomizer)
    (input : ℕ → ℕ → Randomizer → Randomizer → K) (project : α → Randomizer)
    (target bound : ℕ) :
    RememberAuthLaw table leaf input project target bound id
      (fun auth => auth.length = bound) (forsRemember target) := by
  intro kp height left right auth valid inRange aligned hl hr
  rw [fors_remember_collect]
  have cert := collect_auth_certified table leaf input project target kp height left right auth
    (by omega) aligned hl hr
  exact ⟨cert.1.trans valid, cert.2⟩

end
end C10Probability
