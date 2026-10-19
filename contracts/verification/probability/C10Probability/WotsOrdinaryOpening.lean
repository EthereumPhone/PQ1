import C10Probability.WotsForestExclusion

/-! Ordinary components of the WOTS opening client. Public-call accounting
bounds variable node guesses while private calls remain in the exact program.
The randomizer search has zero variable charge, including exhaustion. -/
namespace C10Probability
noncomputable section

theorem selected_budget_of_public {K P α R : Type*} (select : Sum K P → Bool)
    (privateFalse : ∀ tail, select (.inr tail) = false) {n : ℕ}
    (program : QueryProgram (Sum K P) α R n) (q : ℕ) (budget : PublicBudget program q) :
    SelectedBudget select program q := by
  induction program generalizing q with
  | done value => trivial
  | query key next ih =>
    cases key with
    | inl key =>
      cases chosen : select (.inl key) <;>
        simp only [SelectedBudget, chosen, Bool.false_eq_true, ↓reduceIte]
      · exact fun reply => selectedBudget_mono select (next reply) (Nat.sub_le q 1)
          (ih reply (q - 1) (budget.2 reply))
      · exact ⟨budget.1, fun reply => ih reply (q - 1) (budget.2 reply)⟩
    | inr tail =>
      simp only [SelectedBudget, privateFalse, Bool.false_eq_true, ↓reduceIte]
      exact fun reply => ih reply q (budget reply)

theorem wots_lift_variable_budget {R : Type*} {n : ℕ}
    (program : QueryProgram WotsQuery Digest R n) (q : ℕ)
    (budget : SelectedBudget nodeVariable program q) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (liftOpening (P := Unit) (H := Digest) program)) q := by
  rw [redact_opening_lift, selectedBudget_mapReturn, selectedBudget_map]
  exact budget

theorem forest_sign_wots_opening_budget (seed : ByteKey) (ht : ℕ) (digest : Digest)
    (shuffle : ByteKey) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (liftOpening (P := Unit) (H := Digest)
        (forestSignProgram id seed ht digest shuffle))) 53386 := by
  apply wots_lift_variable_budget
  exact selected_budget_of_public nodeVariable node_private_candidate_excluded _ _
    (forest_sign_public seed ht digest shuffle)

theorem randomizer_wots_cut_excluded (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root : ByteKey) (m : ℕ) (bound : m ≤ 2 ^ 32)
    (seedWidth : seed.length = 32) (rootWidth : root.length = 32)
    (messageWidth : message.length = 32) :
    QueryExclusion (fun key => decide (key = wotsCutIncoming seed target previous))
      (fun _ => True) (randomizerUnderProgram id random message seed root m bound) := by
  rw [randomizerUnderProgram, mapProgram_id, privateRandomizerProgram, queryExclusion_cast]
  apply query_exclusion_derived
  · intro key member
    obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
    apply decide_eq_false
    apply wots_foreign_private_ne_incoming
    simp only [counter_key_length, rTailStem, List.length_append, messageWidth]
    omega
  · intro value
    apply decide_eq_false
    apply wots_public_width_ne_incoming
    rw [hmsg_randomizer_length seed root message value seedWidth rootWidth messageWidth, seedWidth]
    decide

theorem randomizer_wots_opening_sealed (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root : ByteKey) (m : ℕ) (bound : m ≤ 2 ^ 32)
    (seedWidth : seed.length = 32) (rootWidth : root.length = 32)
    (messageWidth : message.length = 32) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (liftOpening (P := Unit) (H := Digest)
        (randomizerUnderProgram id random message seed root m bound)) := by
  exact query_exclusion_sealed _ _
    (randomizer_wots_cut_excluded seed target previous random message root m bound
      seedWidth rootWidth messageWidth)

theorem randomizer_wots_opening_budget (random message seed root : ByteKey)
    (m : ℕ) (bound : m ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (liftOpening (P := Unit) (H := Digest)
        (randomizerUnderProgram id random message seed root m bound))) 0 := by
  exact wots_lift_variable_budget _ _
    (randomizer_variable_budget random message seed root m bound)

end
end C10Probability
