import C10Probability.CandidateBudget
import C10Probability.MemoPresample

/-! Small executions expose the shared-cache and adaptive-opening boundaries.
The two equality tests succeed with probability3/4 rather than an independence
guess of1/2; explicit revelation keeps the real result but removes its charge. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def openingPublicFirst : OpeningProgram Bool Unit Bool Bool Bool 2 :=
  .query false (fun first => .commit () (fun second => .done (first != second)))

def openingCommitFirst : OpeningProgram Bool Unit Bool Bool Bool 2 :=
  .commit () (fun first => .query false (fun second => .done (first != second)))

def openingRepeat : OpeningProgram Bool Unit Bool Bool Bool 2 :=
  .commit () (fun first => .commit () (fun second => .done (first == second)))

def openingSuccess {n : ℕ} (program : OpeningProgram Bool Unit Bool Bool Bool n) : PMF Bool :=
  (openingGame fairReply fairReply (fun secret (_ : Unit) => secret) id (PMF.pure program)).map
    (fun out => decide (out.1 ∈ openingCandidates (fun guess => {guess}) out.2))

theorem opening_public_first_mass : openingSuccess openingPublicFirst true = (3 : ℝ≥0∞) / 4 := by
  simp only [openingSuccess, openingGame, PMF.pure_bind, PMF.map_bind, PMF.map_comp, Function.comp_def]
  rw [PMF.bind_apply, tsum_fintype, Fintype.sum_bool]
  simp [openingPublicFirst, evalOpening, memoQuery,
    openingRetain, openingCandidates, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness), ENNReal.toReal_mul,
    ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

theorem opening_commit_first_mass : openingSuccess openingCommitFirst true = (3 : ℝ≥0∞) / 4 := by
  simp only [openingSuccess, openingGame, PMF.pure_bind, PMF.map_bind, PMF.map_comp, Function.comp_def]
  rw [PMF.bind_apply, tsum_fintype, Fintype.sum_bool]
  simp [openingCommitFirst, evalOpening, memoQuery,
    openingRetain, openingCandidates, PMF.map_bind, PMF.bind_map, PMF.pure_map,
    Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]
  apply (ENNReal.toReal_eq_toReal_iff' (by finiteness) (by finiteness)).mp
  rw [ENNReal.toReal_add (by finiteness) (by finiteness), ENNReal.toReal_mul,
    ENNReal.toReal_add (by finiteness) (by finiteness)]
  norm_num [ENNReal.toReal_mul]

theorem opening_repeated_cached (secret : Bool) :
    (evalOpening fairReply (fun value (_ : Unit) => value) id secret openingRepeat
      (fun _ => none) false).map (fun out => out.value) = PMF.pure true := by
  simp [openingRepeat, evalOpening, memoQuery, PMF.map_bind, PMF.pure_map]

theorem opening_constant_guess_mass :
    openingSuccess (.commit () (fun _ => .done (n := 0) false)) true = (1 : ℝ≥0∞) / 2 := by
  simp [openingSuccess, openingGame, evalOpening, memoQuery, openingRetain, openingCandidates,
    PMF.map_bind, PMF.pure_map, Function.comp_def, PMF.bind_apply, fairReply, tsum_fintype]

theorem opening_reveal_retains_full (secret : Bool × Bool) (table : Memo Bool Bool) :
    evalOpening fairReply (fun value (_ : Unit) => value) Prod.fst secret
      (.reveal (fun value => .done (n := 0) value)) table false =
        PMF.pure ⟨secret, table, true⟩ := by rfl

theorem opening_reveal_cannot_guess :
    openingSuccess (.reveal (fun secret => .done (n := 0) secret)) true = 0 := by
  simp [openingSuccess, openingGame, evalOpening, openingRetain, openingCandidates,
    PMF.map_bind, PMF.pure_map]

theorem opening_commit_then_reveal_cannot_guess :
    openingSuccess (.commit () (fun _ => .reveal (fun secret => .done (n := 0) secret))) true = 0 := by
  simp [openingSuccess, openingGame, evalOpening, memoQuery, openingRetain, openingCandidates,
    PMF.map_bind, PMF.pure_map]

theorem opening_fixed_candidates_still_hit :
    variableCandidate (some : Bool → Option Bool) {false, true} false = false ∧
    variableCandidate (some : Bool → Option Bool) {false, true} true = false ∧
    ((fairReply.map fun secret => decide (secret ∈
      prefixCandidates (some : Bool → Option Bool) [false, true])) true) = 1 := by
  simp [variableCandidate, prefixCandidates, fairReply]
  exact ENNReal.mul_inv_cancel (by norm_num) (by norm_num)

theorem opening_unused_presample_removed (secret : Bool) :
    (restoreTarget false (⟨(), Function.update (fun _ : Bool => none) false (some secret), []⟩ :
      TraceOutput Bool Bool Unit)).2 false = none := by
  simp [restoreTarget]

theorem opening_used_presample_retained (secret : Bool) :
    (restoreTarget false (⟨(), Function.update (fun _ : Bool => none) false (some secret), [false]⟩ :
      TraceOutput Bool Bool Unit)).2 false = some secret := by
  simp [restoreTarget]

theorem opening_other_presample_preserved (secret reply : Bool) :
    (restoreTarget false (⟨(), Function.update (Function.update (fun _ : Bool => none)
      false (some secret)) true (some reply), [true]⟩ : TraceOutput Bool Bool Unit)).2 true =
        some reply := by
  simp [restoreTarget]

end
end C10Probability
