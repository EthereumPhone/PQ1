import C10Probability.ReplayedOpeningEvent

/-! An adaptive ordinary prefix selects an incoming key, then obtains the
full reply used for an opening. Freshness here is a proved property of that
prefix execution; it is not required of the later actual client. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
variable {K α S R T : Type*} [DecidableEq K]

def openingTargetSetup {n : ℕ} (prelude : QueryProgram K α T n)
    (target : T → K) (project : α → S) : QueryProgram K α S (1 + n) :=
  bindProgram prelude (fun value => .query (target value) (fun reply => .done (project reply)))

theorem opening_target_setup_eval (p : PMF α) {n : ℕ} (prelude : QueryProgram K α T n)
    (target : T → K) (project : α → S) (table : Memo K α) :
    evalProgram p (openingTargetSetup prelude target project) table =
      (evalProgram p prelude table).bind fun before =>
        (memoQuery p before.2 (target before.1)).map (fun reply => (project reply.1, reply.2)) := by
  rw [openingTargetSetup, evalProgram_bind]
  simp only [evalProgram, PMF.map, Function.comp_def]

theorem opening_target_setup_fresh (p : PMF α) {n : ℕ} (prelude : QueryProgram K α T n)
    (target : T → K) (project : α → S) (table : Memo K α)
    (fresh : ∀ before ∈ (evalProgram p prelude table).support, before.2 (target before.1) = none) :
    evalProgram p (openingTargetSetup prelude target project) table =
      (evalProgram p prelude table).bind fun before =>
        p.map (fun secret => (project secret, Function.update before.2 (target before.1) (some secret))) := by
  rw [opening_target_setup_eval]
  apply bind_eq_of_support
  intro before supported
  rw [memoQuery_fresh p before.2 (target before.1) (fresh before supported), PMF.map_comp]
  rfl

def preparedOpeningGame (p : PMF α) {m n : ℕ}
    (setup : QueryProgram K α S m) (client : QueryProgram K α R n) (table : Memo K α) :
    PMF (S × (R × Memo K α)) :=
  (evalProgram p setup table).bind fun warm =>
    (evalProgram p client warm.2).map (fun out => (warm.1, out))

def preparedOpeningEvent (candidates : R → Finset S)
    (excluded : R → Memo K α → Prop) : Set (S × (R × Memo K α)) :=
  {out | ¬ excluded out.2.1 out.2.2 ∧ out.1 ∈ candidates out.2.1}

theorem replayed_opening_prepared_le (p : PMF α) {m n : ℕ}
    (setup : QueryProgram K α S m) (client : QueryProgram K α R n) (table : Memo K α)
    (candidates : R → Finset S) (excluded : R → Memo K α → Prop) :
    (evalProgram p client table).toOuterMeasure (replayedOpeningEvent setup candidates excluded) ≤
      (preparedOpeningGame p setup client table).toOuterMeasure (preparedOpeningEvent candidates excluded) := by
  simpa only [preparedOpeningGame, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, preparedOpeningEvent, Set.preimage_setOf_eq] using
    replayed_opening_presample_le p setup client table candidates excluded

theorem prepared_opening_target_fresh (p : PMF α) {m n : ℕ}
    (prelude : QueryProgram K α T m) (target : T → K) (project : α → S)
    (client : QueryProgram K α R n) (table : Memo K α)
    (fresh : ∀ before ∈ (evalProgram p prelude table).support, before.2 (target before.1) = none) :
    preparedOpeningGame p (openingTargetSetup prelude target project) client table =
      (evalProgram p prelude table).bind fun before => p.bind fun secret =>
        (evalProgram p client (Function.update before.2 (target before.1) (some secret))).map
          (fun out => (project secret, out)) := by
  rw [preparedOpeningGame, opening_target_setup_fresh p prelude target project table fresh,
    PMF.bind_bind]
  simp only [PMF.bind_map, Function.comp_def]

end
end C10Probability
