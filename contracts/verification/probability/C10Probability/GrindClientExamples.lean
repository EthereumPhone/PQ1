import C10Probability.GrindSession

/-! Small executions check composition and compilation without using the
grinder compiler equalities as their oracle. Repeated calls are memoized. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem composed_cached_reply :
    (evalProgram fairReply
      (bindProgram (.query false (fun first => .done (n := 0) first))
        (fun first => .query false (fun second => .done (n := 0) (decide (first = second)))))
      (fun _ => none)).map Prod.fst = PMF.pure true := by
  simp [bindProgram, evalProgram, evalProgram_cast, evalProgram_reserve,
    memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map, Function.comp_def]

theorem composed_reply_dependent_mass :
    ((evalProgram fairReply
      (bindProgram (.query false (fun first => .done (n := 0) first))
        (fun first => .query first (fun second => .done (n := 0) second)))
      (fun _ => none)).map Prod.fst) true = (1 : ℝ≥0∞) / 4 := by
  simp only [bindProgram, evalProgram, evalProgram_cast, evalProgram_reserve,
    memoQuery, PMF.map_bind, PMF.bind_map, PMF.pure_map, Function.comp_def]
  rw [PMF.bind_apply, tsum_fintype, Fintype.sum_bool]
  simp [PMF.bind_map, Function.comp_def, fairReply]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  norm_num [ENNReal.toReal_mul]

theorem compiled_immediate_state :
    evalProgram (PMF.pure true)
      (derivedProgram id id (fun _ => (1 : ℕ)) id 0 [0, 2]) (fun _ => none) =
      PMF.pure (some (0, true, true),
        Function.update (Function.update (fun _ => none) 0 (some true)) 1 (some true)) := by
  simp [derivedProgram, evalProgram_cast, evalProgram, memoQuery, PMF.pure_map]

theorem compiled_cached_rejection :
    evalProgram (PMF.pure true)
      (derivedProgram id id (fun _ => (1 : ℕ)) id 3 [0])
      (fun key => if key = 1 then some false else none) =
      PMF.pure (none,
        Function.update (fun key => if key = 1 then some false else none) 0 (some true)) := by
  simp [derivedProgram, evalProgram_cast, evalProgram, memoQuery, PMF.pure_map]

theorem compiled_cached_first_label :
    evalProgram (PMF.pure false)
      (derivedProgram id id (fun value => if value then (1 : ℕ) else 2) (fun _ => true) 5 [0])
      (fun key => if key = 0 then some true else none) =
      PMF.pure (some (5, true, false),
        Function.update (fun key => if key = 0 then some true else none) 1 (some false)) := by
  simp [derivedProgram, evalProgram_cast, evalProgram, memoQuery, PMF.pure_map]

def retryExampleTable : Memo ℕ Bool :=
  fun key => if key = 0 then some true else if key = 1 ∨ key = 2 then some false else none

theorem compiled_retry_counter_state :
    evalProgram (PMF.pure true)
      (derivedProgram id id (fun value => if value then (2 : ℕ) else 3) id 6 [0, 1, 4])
      retryExampleTable =
      PMF.pure (some (7, false, true), Function.update retryExampleTable 3 (some true)) := by
  simp [derivedProgram, evalProgram_cast, evalProgram, memoQuery, PMF.pure_map, retryExampleTable]

def repeatPrivateGrind : QueryProgram (Sum Bool Unit) Bool Bool 4 :=
  bindProgram
    (derivedProgram Sum.inr id (fun _ => Sum.inl false) (fun _ => true) 0 [()])
    (fun first => bindProgram
      (derivedProgram Sum.inr id (fun _ => Sum.inl false) (fun _ => true) 0 [()])
      (fun second => .done (n := 0) (decide (first = second))))

theorem repeated_private_grind_cached :
    (evalProgram fairReply repeatPrivateGrind (fun _ => none)).map Prod.fst = PMF.pure true := by
  simp [repeatPrivateGrind, evalProgram_bind, derivedProgram, evalProgram_cast,
    evalProgram, memoQuery, PMF.map_bind, PMF.bind_map,
    PMF.pure_map, Function.comp_def]

theorem shared_session_zero (request : GrindRequest) :
    sharedGrindSession (PMF.pure (.done (n := 0) ())) (fun _ => request)
      (fun _ out => .done (n := 0) out) 0 (by decide) = PMF.pure none := by
  simp [sharedGrindSession, mapProgram, evalProgram, sharedRandomizerSearch,
    counterSchedule, derivedMemoGrind, PMF.pure_map]

theorem independent_session_zero (request : GrindRequest) :
    independentGrindSession (PMF.pure (.done (n := 0) ())) (fun _ => request)
      (fun _ out => .done (n := 0) out) 0 (by decide) = PMF.pure none := by
  simp [independentGrindSession, evalProgram, privateRandomizerSearch_zero, PMF.pure_map]

end
end C10Probability
