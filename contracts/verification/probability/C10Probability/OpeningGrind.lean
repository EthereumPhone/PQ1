import C10Probability.ForsQuerySeparation

/-! Candidate accounting for the actual bounded grinders. R private-table
calls contribute no public candidate; all H_msg and counter candidates remain
in the fixed charged set. Cached calls and exhausted searches are preserved. -/
namespace C10Probability
noncomputable section
variable {K P L α R : Type*}

theorem query_exclusion_selected (select : K → Bool) {n : ℕ} (program : QueryProgram K α R n)
    (excluded : QueryExclusion select (fun _ => True) program) : SelectedBudget select program 0 := by
  induction program with
  | done value => trivial
  | query key next ih =>
    simp only [SelectedBudget, excluded.1, Bool.false_eq_true, ↓reduceIte]
    exact fun reply => ih reply (excluded.2 reply)

theorem query_exclusion_derived (select : K → Bool) (firstKey : P → K) (derive : α → L)
    (encode : L → K) (accept : α → Bool) (start : ℕ) (keys : List P)
    (first : ∀ key ∈ keys, select (firstKey key) = false)
    (second : ∀ value, select (encode value) = false) :
    QueryExclusion select (fun _ => True) (derivedProgram firstKey derive encode accept start keys) := by
  induction keys generalizing start with
  | nil => trivial
  | cons key rest ih =>
    rw [derivedProgram, queryExclusion_cast]
    refine ⟨first key (by simp), fun reply => ⟨second (derive reply), fun value => ?_⟩⟩
    cases accepted : accept value
    · simp only [accepted, Bool.false_eq_true, ↓reduceIte]
      exact ih (start + 1) (fun key member => first key (by simp [member]))
    · simp only [accepted, ↓reduceIte, QueryExclusion]

theorem randomizer_fors_excluded (target : ForsTarget) (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) :
    QueryExclusion (forsTargetSelect target) (fun _ => True)
      (randomizerUnderProgram id random message seed root m hm) := by
  rw [randomizerUnderProgram, mapProgram_id, privateRandomizerProgram, queryExclusion_cast]
  apply query_exclusion_derived
  · intro key member
    obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
    simp only [forsTargetSelect, fors_target_not_counter, decide_false]
  · intro value
    simp only [Function.comp_apply, forsTargetSelect, fors_target_not_public, decide_false]

def nodeVariable : WotsQuery → Bool := variableCandidate nodeQueryDecode fixedNodeCandidates

theorem randomizer_variable_budget (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) :
    SelectedBudget nodeVariable (randomizerUnderProgram id random message seed root m hm) 0 := by
  apply query_exclusion_selected
  rw [randomizerUnderProgram, mapProgram_id, privateRandomizerProgram, queryExclusion_cast]
  apply query_exclusion_derived
  · intro key _
    exact node_private_candidate_excluded key
  · intro value
    exact node_hmsg_candidate_fixed seed root message value

theorem opening_lift_variable_budget {R : Type*} {n : ℕ}
    (program : QueryProgram WotsQuery Digest R n) (q : ℕ)
    (budget : SelectedBudget nodeVariable program q) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (liftOpening (P := ByteKey) (H := Digest) program)) q := by
  rw [redact_opening_lift, selectedBudget_mapReturn, selectedBudget_map]
  exact budget

theorem wots_sign_variable_budget (seed : ByteKey) (layer tree kp : ℕ)
    (message shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    SelectedBudget nodeVariable (wotsSignProgram id seed layer tree kp message shuffle n hb) 252 := by
  rw [wotsSignProgram, selectedBudget_cast]
  apply selectedBudget_bind _ _ _ 0 252
  · apply query_exclusion_selected
    rw [queryExclusion_map, wotsCountProgram, queryExclusion_cast]
    apply queryExclusion_count
    intro key member
    obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
    exact node_counter_candidate_fixed _ _
  · intro found
    exact selectedBudget_total _ _

theorem layer_sign_variable_budget (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    SelectedBudget nodeVariable (layerSignProgram id seed layer tree leaf message shuffle n hb) 177511 := by
  rw [layerSignProgram, selectedBudget_cast]
  apply selectedBudget_bind _ _ _ 177151 360 (selectedBudget_total _ _)
  intro built
  apply selectedBudget_bind _ _ _ 1 359 (selectedBudget_total _ _)
  intro subseed
  exact selectedBudget_bind _ _ _ 252 107
    (wots_sign_variable_budget seed layer tree leaf (nodeValueBytes message) subseed n hb)
    (fun _ => selectedBudget_total _ _)

theorem hypertree_sign_variable_budget (seed shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (steps layer index : ℕ) (current : Randomizer) (signatures : List LayerSignature) :
    SelectedBudget nodeVariable
      (hypertreeSignProgram id seed shuffle n hb steps layer index current signatures) (steps * 177511) := by
  induction steps generalizing layer index current signatures with
  | zero => rw [hypertreeSignProgram]; trivial
  | succ steps ih =>
    rw [hypertreeSignProgram, selectedBudget_cast, Nat.succ_mul,
      show steps * 177511 + 177511 = 177511 + steps * 177511 by omega]
    apply selectedBudget_bind _ _ _ 177511 (steps * 177511)
      (layer_sign_variable_budget _ _ _ _ _ _ _ _)
    intro signed
    cases signed with
    | none => trivial
    | some signed => exact ih _ _ _ _

end
end C10Probability
