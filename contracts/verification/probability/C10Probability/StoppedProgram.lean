import C10Probability.QueryMap
import C10Probability.Transfer

/-! Stopping at a designated query is proof instrumentation. The compared
experiments continue to execute the ordinary memoized interpreter. The two
event inequalities below explicitly account for the stopped probability. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K L α R : Type*} [DecidableEq L]

def stoppedProgram (p : PMF α) (encode : K → L) (bad : K → Bool) :
    {n : ℕ} → QueryProgram K α R n → Memo L α → PMF (Option R)
  | _, .done value, _ => PMF.pure (some value)
  | _, .query key next, table =>
      if bad key then PMF.pure none else
        (memoQuery p table (encode key)).bind fun reply =>
          stoppedProgram p encode bad (next reply.1) reply.2

def retainEvent (event : Set R) : Set (Option R) :=
  {out | match out with | none => False | some value => value ∈ event}

theorem stoppedProgram_retained_le (p : PMF α) (encode : K → L) (bad : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n) (table : Memo L α) (event : Set R) :
    (stoppedProgram p encode bad program table).toOuterMeasure (retainEvent event) ≤
      ((evalProgram p (mapProgram encode program) table).map Prod.fst).toOuterMeasure event := by
  induction program generalizing table with
  | done value =>
    classical
    by_cases hv : value ∈ event <;>
      simp [stoppedProgram, mapProgram, evalProgram, PMF.pure_map,
        PMF.toOuterMeasure_pure_apply, retainEvent, hv]
  | query key next ih =>
    cases hb : bad key
    · simp only [stoppedProgram, hb, Bool.false_eq_true, ↓reduceIte, mapProgram,
        evalProgram, PMF.map_bind, PMF.toOuterMeasure_bind_apply]
      apply ENNReal.tsum_le_tsum
      intro reply
      exact mul_le_mul_right (ih reply.1 reply.2) _
    · simp [stoppedProgram, hb, PMF.toOuterMeasure_pure_apply, retainEvent]

theorem fullProgram_event_le (p : PMF α) (encode : K → L) (bad : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n) (table : Memo L α) (event : Set R) :
    ((evalProgram p (mapProgram encode program) table).map Prod.fst).toOuterMeasure event ≤
      (stoppedProgram p encode bad program table).toOuterMeasure
        (retainEvent event ∪ {none}) := by
  induction program generalizing table with
  | done value =>
    classical
    by_cases hv : value ∈ event <;>
      simp [stoppedProgram, mapProgram, evalProgram, PMF.pure_map,
        PMF.toOuterMeasure_pure_apply, retainEvent, hv, Set.mem_insert_iff]
  | query key next ih =>
    cases hb : bad key
    · simp only [stoppedProgram, hb, Bool.false_eq_true, ↓reduceIte, mapProgram,
        evalProgram, PMF.map_bind, PMF.toOuterMeasure_bind_apply]
      apply ENNReal.tsum_le_tsum
      intro reply
      exact mul_le_mul_right (ih reply.1 reply.2) _
    · simpa [stoppedProgram, hb, PMF.toOuterMeasure_pure_apply] using
        event_mass_le_one ((evalProgram p (mapProgram encode (.query key next)) table).map
          Prod.fst) event

theorem fullProgram_event_charge (p : PMF α) (encode : K → L) (bad : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n) (table : Memo L α) (event : Set R) :
    ((evalProgram p (mapProgram encode program) table).map Prod.fst).toOuterMeasure event ≤
      (stoppedProgram p encode bad program table).toOuterMeasure (retainEvent event) +
        stoppedProgram p encode bad program table none := by
  apply (fullProgram_event_le p encode bad program table event).trans
  simpa only [PMF.toOuterMeasure_apply_singleton] using
    MeasureTheory.measure_union_le (μ := (stoppedProgram p encode bad program table).toOuterMeasure)
      (retainEvent event) {none}

def censorTrace (bad : K → Bool) (out : TraceOutput K α R) : Option R :=
  if out.queries.any bad then none else some out.value

theorem stoppedProgram_trace [DecidableEq K] (p : PMF α) (bad : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n) (table : Memo K α) :
    (traceProgram p program table).map (censorTrace bad) =
      stoppedProgram p id bad program table := by
  induction program generalizing table with
  | done value => simp [traceProgram, censorTrace, stoppedProgram, PMF.pure_map]
  | query key next ih =>
    cases hb : bad key
    · simp only [traceProgram, PMF.map_bind, PMF.map_comp, Function.comp_def,
        censorTrace, List.any_cons, hb, Bool.false_or, stoppedProgram,
        Bool.false_eq_true, ↓reduceIte, id_eq]
      congr 1
      funext reply
      exact ih reply.1 reply.2
    · simp [traceProgram, Function.comp_def, censorTrace, hb, stoppedProgram,
        PMF.map, PMF.bind_const]

theorem stoppedProgram_abort [DecidableEq K] (p : PMF α) (bad : K → Bool)
    {n : ℕ} (program : QueryProgram K α R n) (table : Memo K α) :
    stoppedProgram p id bad program table none =
      ((traceProgram p program table).map (fun out => out.queries.any bad)) true := by
  rw [← stoppedProgram_trace, PMF.map_apply, PMF.map_apply]
  apply tsum_congr
  intro out
  cases hb : out.queries.any bad <;> simp [censorTrace, hb]

end
end C10Probability
