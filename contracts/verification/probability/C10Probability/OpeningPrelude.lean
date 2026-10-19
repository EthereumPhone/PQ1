import C10Probability.OpeningGuess
import C10Probability.OpeningComposition
import C10Probability.DerivedGrind

/-! An ordinary adaptive prefix generates the cache used by an opening
context. The selected secret may be sampled before or after that prefix because
the prefix does not receive it. This is an exact staged-execution equality;
no arbitrary initial-cache independence premise is added to the bound. -/
namespace C10Probability
open scoped ENNReal
noncomputable section
variable {K P α H S R T : Type*} [DecidableEq K]

theorem eval_opening_prelude (p : PMF α) (encode : S → P → K) (project : H → S)
    (secret : H) {n m : ℕ} (prelude : QueryProgram K α T n)
    (after : T → OpeningProgram K P α H R m) (table : Memo K α) (opened : Bool) :
    evalOpening p encode project secret (bindOpening (liftOpening prelude) after) table opened =
      (evalProgram p prelude table).bind fun warm =>
        evalOpening p encode project secret (after warm.1) warm.2 opened := by
  rw [eval_opening_bind, eval_opening_lift, PMF.bind_map]
  rfl

theorem opening_game_prelude (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (project : H → S) {n m : ℕ}
    (prelude : QueryProgram K α T n) (after : T → OpeningProgram K P α H R m) :
    openingGame secretDraw p encode project (PMF.pure (bindOpening (liftOpening prelude) after)) =
      (evalProgram p prelude (fun _ => none)).bind fun warm => secretDraw.bind fun secret =>
        (evalOpening p encode project secret (after warm.1) warm.2 false).map
          (fun out => (project secret, openingRetain out)) := by
  simp only [openingGame, PMF.pure_bind, eval_opening_prelude, PMF.map_bind]
  exact PMF.bind_comm _ _ _

theorem opening_prelude_candidate_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq P] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (decode : K → Option S) (project : H → S)
    (uniform : secretDraw.map project = PMF.uniformOfFintype S)
    (prefixLaw : ∀ secret label, decode (encode secret label) = some secret)
    (labels : ∀ secret, Function.Injective (encode secret)) {n m : ℕ}
    (prelude : QueryProgram K α T n) (after : T → OpeningProgram K P α H R m)
    (q c : ℕ)
    (budget : PublicBudget (redactOpening (bindOpening (liftOpening prelude) after)) q)
    (candidates : R → Finset S) (count : ∀ value, (candidates value).card ≤ c) :
    ((evalProgram p prelude (fun _ => none)).bind fun warm => secretDraw.bind fun secret =>
      (evalOpening p encode project secret (after warm.1) warm.2 false).map
        (fun out => (project secret, openingRetain out))).toOuterMeasure
          (candidateEvent (openingCandidates candidates)) ≤
            ((q + c : ℕ) : ℝ≥0∞) / Fintype.card S := by
  rw [← opening_game_prelude]
  apply opening_candidate_bound secretDraw p encode decode project uniform prefixLaw labels
    (PMF.pure (bindOpening (liftOpening prelude) after)) q c _ candidates count
  intro program supported
  have equal : program = bindOpening (liftOpening prelude) after := by
    simpa only [PMF.mem_support_pure_iff] using supported
  simpa only [equal] using budget

end
end C10Probability
