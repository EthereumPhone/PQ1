import C10Probability.PrivateTransfer

/-! A hidden-node commitment uses the existing shared-key interpreter. Its
public query transcript is not assumed independent of the node. The explicit
relabeling charge covers guesses before and after a commitment, including
cached calls; only the separated experiment permits late sampling. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K P S α R : Type*}

def candidateEvent (candidates : R → Finset S) : Set (S × R) :=
  {out | out.1 ∈ candidates out.2}

def independentCandidateGame (secretDraw : PMF S) (result : PMF R) : PMF (S × R) :=
  secretDraw.bind fun secret => result.map fun value => (secret, value)

theorem independent_candidate_late (secretDraw : PMF S) (result : PMF R) :
    independentCandidateGame secretDraw result =
      result.bind fun value => secretDraw.map fun secret => (secret, value) := by
  exact PMF.bind_comm secretDraw result (fun secret value => PMF.pure (secret, value))

theorem event_decide_mass (p : PMF α) (event : Set α) [DecidablePred (· ∈ event)] :
    (p.map (fun value => decide (value ∈ event))) true = p.toOuterMeasure event := by
  rw [← PMF.toOuterMeasure_apply_singleton, PMF.toOuterMeasure_map_apply]
  congr 1
  ext value
  simp

theorem uniform_candidate_mass [Fintype S] [Nonempty S] [DecidableEq S]
    (candidates : Finset S) :
    (PMF.uniformOfFintype S).toOuterMeasure {secret | secret ∈ candidates} =
      (candidates.card : ℝ≥0∞) / Fintype.card S := by
  rw [← event_decide_mass]
  simpa [PMF.map_apply] using uniform_seen_mass candidates

theorem independent_candidate_bound [Fintype S] [Nonempty S] [DecidableEq S]
    (result : PMF R) (candidates : R → Finset S) (m : ℕ)
    (bound : ∀ value ∈ result.support, (candidates value).card ≤ m) :
    (independentCandidateGame (PMF.uniformOfFintype S) result).toOuterMeasure
      (candidateEvent candidates) ≤ (m : ℝ≥0∞) / Fintype.card S := by
  rw [independent_candidate_late, PMF.toOuterMeasure_bind_apply]
  simp only [PMF.toOuterMeasure_map_apply, candidateEvent, Set.preimage_setOf_eq,
    uniform_candidate_mass]
  calc
    _ ≤ ∑' value, result value * ((m : ℝ≥0∞) / Fintype.card S) := by
      apply ENNReal.tsum_le_tsum
      intro value
      by_cases supported : value ∈ result.support
      · apply mul_le_mul_right
        apply ENNReal.div_le_div_right
        exact_mod_cast bound value supported
      · have hz : result value = 0 := (PMF.apply_eq_zero_iff _ value).mpr supported
        simp [hz]
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

def commitmentGame [DecidableEq K] (secretDraw : PMF S) (p : PMF α)
    (encode : S → P → K) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) : PMF (S × R) :=
  secretDraw.bind fun secret =>
    (privateSharedAt p encode secret client).map fun value => (secret, value)

theorem commitment_candidate_comparison [DecidableEq K] [DecidableEq P] [DecidableEq S]
    (secretDraw : PMF S) (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) (candidates : R → Finset S) :
    (commitmentGame secretDraw p encode client).toOuterMeasure (candidateEvent candidates) ≤
      (independentCandidateGame secretDraw (privateIndependent p client)).toOuterMeasure
        (candidateEvent candidates) + (secretDraw.bind (privateGuess p decode client)) true := by
  simp only [commitmentGame, independentCandidateGame, PMF.toOuterMeasure_bind_apply,
    PMF.toOuterMeasure_map_apply, candidateEvent, Set.preimage_setOf_eq,
    PMF.bind_apply, ← ENNReal.tsum_add]
  apply ENNReal.tsum_le_tsum
  intro secret
  simpa only [mul_add] using mul_le_mul_right
    (private_client_bounds p encode decode prefixLaw tails secret client
      {value | secret ∈ candidates value}).1 (secretDraw secret)

theorem commitment_candidate_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (p : PMF α) (encode : S → P → K)
    (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) (q m : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q)
    (candidates : R → Finset S)
    (count : ∀ value ∈ (privateIndependent p client).support, (candidates value).card ≤ m) :
    (commitmentGame (PMF.uniformOfFintype S) p encode client).toOuterMeasure
      (candidateEvent candidates) ≤ ((q + m : ℕ) : ℝ≥0∞) / Fintype.card S := by
  have queryBound : ((PMF.uniformOfFintype S).bind (privateGuess p decode client)) true ≤
      (q : ℝ≥0∞) / Fintype.card S := by
    simpa only [privateGuess, secretPrelude, PMF.map_bind, PMF.map_comp, Function.comp_def] using
      private_prefix_bound decode p client (fun _ => none) q budget
  have bound := (commitment_candidate_comparison (PMF.uniformOfFintype S) p encode decode
    prefixLaw tails client candidates).trans (add_le_add
      (independent_candidate_bound (privateIndependent p client) candidates m count) queryBound)
  simpa only [← ENNReal.add_div, ← Nat.cast_add, Nat.add_comm m q] using bound

theorem commitment_candidate_bound_real [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (p : PMF α) (encode : S → P → K)
    (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) (q m : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q)
    (candidates : R → Finset S)
    (count : ∀ value ∈ (privateIndependent p client).support, (candidates value).card ≤ m) :
    ((commitmentGame (PMF.uniformOfFintype S) p encode client).toOuterMeasure
      (candidateEvent candidates)).toReal ≤ (q + m : ℕ) / (Fintype.card S : ℝ) := by
  have bound := ENNReal.toReal_mono
    (show ((q + m : ℕ) : ℝ≥0∞) / Fintype.card S ≠ ⊤ by
      exact ENNReal.div_ne_top (by simp) (by simp))
    (commitment_candidate_bound p encode decode prefixLaw tails client q m budget candidates count)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast] using bound

end
end C10Probability
