import C10Probability.PreludeBound

/-! Finite independent witnesses for public-history guessing, cache origins
and secret independence. The leaked-secret experiment intentionally uses a
different interface, where the client receives the secret. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def fixedGuess : QueryProgram Bool Bool Bool 1 :=
  .query false (fun reply => .done reply)

def repeatedGuess : QueryProgram Bool Bool Bool 2 :=
  .query false (fun first => .query false (fun second => .done (first && second)))

theorem trace_cached_repeats :
    traceProgram (PMF.pure true) repeatedGuess (fun _ => some false) =
      PMF.pure (⟨false, fun _ => some false, [false, false]⟩ : TraceOutput Bool Bool Bool) := by
  simp [traceProgram, repeatedGuess, memoQuery, PMF.pure_map]

theorem trace_prefilled_return :
    traceProgram fairReply (.done (n := 0) true) (fun _ : Bool => some false) =
      PMF.pure (⟨true, fun _ => some false, []⟩ : TraceOutput Bool Bool Bool) := by rfl

theorem trace_adaptive_second_key :
    ((traceProgram fairReply adaptiveBool (fun _ => none)).map
      (fun out => decide (out.queries = [false, true]))) true = (1 : ℝ≥0∞) / 2 := by
  simp [traceProgram, adaptiveBool, memoQuery, PMF.map_bind, PMF.bind_map,
    PMF.pure_map, Function.comp_def, fairReply]

theorem repeated_prefix_single_candidate :
    prefixCandidates (some : Bool → Option Bool) [false, false] = {false} := by
  simp [prefixCandidates]

theorem absent_prefix_skipped :
    prefixCandidates (fun key : Bool => if key then some true else none) [false, true] =
      {true} := by simp [prefixCandidates]

theorem fixed_guess_mass :
    ((secretPrelude fairReply fairReply (PMF.pure fixedGuess) (fun _ => none)).map
      (prefixHit (some : Bool → Option Bool))) true = (1 : ℝ≥0∞) / 2 := by
  simp [secretPrelude, randomizedTrace, traceProgram, fixedGuess, memoQuery, prefixHit,
    prefixCandidates, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]

theorem repeated_guess_mass :
    ((secretPrelude fairReply fairReply (PMF.pure repeatedGuess) (fun _ => none)).map
      (prefixHit (some : Bool → Option Bool))) true = (1 : ℝ≥0∞) / 2 := by
  simp [secretPrelude, randomizedTrace, traceProgram, repeatedGuess, memoQuery, prefixHit,
    prefixCandidates, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]

theorem adaptive_guess_mass :
    ((secretPrelude fairReply fairReply (PMF.pure adaptiveBool) (fun _ => none)).map
      (prefixHit (some : Bool → Option Bool))) true = (3 : ℝ≥0∞) / 4 := by
  simp [secretPrelude, randomizedTrace, traceProgram, adaptiveBool, memoQuery, prefixHit,
    prefixCandidates, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  calc
    _ = 3 * ((2 : ℝ≥0∞)⁻¹) ^ 2 := by ring
    _ = 3 / 4 := by rw [← ENNReal.inv_pow]; norm_num [div_eq_mul_inv]

def leakedSecretGuess : PMF Bool :=
  fairReply.bind fun secret =>
    (traceProgram fairReply (.query secret (fun reply => .done (n := 0) reply))
      (fun _ => none)).map fun out => prefixHit (some : Bool → Option Bool) (secret, out)

theorem leaked_secret_certain : leakedSecretGuess true = 1 := by
  simp [leakedSecretGuess, traceProgram, memoQuery, prefixHit, prefixCandidates,
    PMF.map_bind, PMF.bind_map, PMF.pure_map, Function.comp_def,
    fairReply]

theorem leaked_secret_exceeds_one_guess : (1 : ℝ≥0∞) / 2 < leakedSecretGuess true := by
  rw [leaked_secret_certain]
  norm_num

theorem prefilled_empty_trace_not_fresh :
    let out : Bool × TraceOutput Bool Bool Bool :=
      (false, ⟨true, fun _ => some false, []⟩)
    prefixHit (some : Bool → Option Bool) out = false ∧ out.2.cache false ≠ none := by
  simp [prefixHit, prefixCandidates]

def emptyRequest : GrindRequest :=
  ⟨[], List.replicate 32 0, List.replicate 32 0, List.replicate 32 0⟩

theorem emptyRequest_valid : RequestValid emptyRequest := by
  unfold RequestValid emptyRequest
  decide

theorem short_request_invalid :
    ¬ RequestValid ⟨[], [], List.replicate 32 0, List.replicate 32 0⟩ := by
  unfold RequestValid
  decide

end
end C10Probability
