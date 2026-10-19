import C10Probability.OpeningGuess
import C10Probability.SelectedBudget

/-! Repeated candidates in a fixed finite set are paid for once. Every other
decodable candidate is retained, including cached and malformed raw calls.
The cardinality argument is independent of any assumed transcript secrecy. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K P α H S R : Type*}

def variableCandidate [DecidableEq S] (decode : K → Option S) (fixed : Finset S)
    (key : K) : Bool :=
  match decode key with
  | none => false
  | some value => decide (value ∉ fixed)

theorem prefix_candidates_variable_cover [DecidableEq S] (decode : K → Option S)
    (fixed : Finset S) (queries : List K) :
    prefixCandidates decode queries ⊆ fixed ∪
      prefixCandidates decode (queries.filter (variableCandidate decode fixed)) := by
  intro secret member
  by_cases known : secret ∈ fixed
  · exact Finset.mem_union_left _ known
  · apply Finset.mem_union_right
    obtain ⟨key, present, decoded⟩ := (prefixCandidates_mem decode queries secret).mp member
    apply (prefixCandidates_mem _ _ _).mpr
    refine ⟨key, List.mem_filter.mpr ⟨present, ?_⟩, decoded⟩
    simp only [variableCandidate, decoded, known, not_false_eq_true, decide_true]

theorem prefix_candidates_variable_card [DecidableEq S] (decode : K → Option S)
    (fixed : Finset S) (queries : List K) :
    (prefixCandidates decode queries).card ≤
      fixed.card + (queries.filter (variableCandidate decode fixed)).length := by
  calc
    _ ≤ (fixed ∪ prefixCandidates decode
        (queries.filter (variableCandidate decode fixed))).card :=
      Finset.card_le_card (prefix_candidates_variable_cover decode fixed queries)
    _ ≤ fixed.card + (prefixCandidates decode
        (queries.filter (variableCandidate decode fixed))).card := Finset.card_union_le _ _
    _ ≤ _ := Nat.add_le_add_left (prefixCandidates_card_le decode _) fixed.card

theorem secretPrelude_variable_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] (decode : K → Option S) (fixed : Finset S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) (q : ℕ)
    (budget : ∀ program ∈ client.support,
      SelectedBudget (variableCandidate decode fixed) program q) :
    ((secretPrelude (PMF.uniformOfFintype S) p client table).map (prefixHit decode)) true ≤
      ((q + fixed.card : ℕ) : ℝ≥0∞) / Fintype.card S := by
  rw [secretPrelude_late, PMF.map_bind, PMF.bind_apply]
  simp only [PMF.map_comp, Function.comp_def, prefixHit, uniform_prefix_mass]
  calc
    _ ≤ ∑' out, (randomizedTrace p client table) out *
        (((q + fixed.card : ℕ) : ℝ≥0∞) / Fintype.card S) := by
      apply ENNReal.tsum_le_tsum
      intro out
      by_cases supported : out ∈ (randomizedTrace p client table).support
      · apply mul_le_mul_right
        apply ENNReal.div_le_div_right
        have lengthBound := randomizedTrace_selected_length p
          (variableCandidate decode fixed) client q budget table out supported
        have cardBound := prefix_candidates_variable_card decode fixed out.queries
        exact_mod_cast (show (prefixCandidates decode out.queries).card ≤ q + fixed.card by omega)
      · have hz := (PMF.apply_eq_zero_iff _ out).mpr supported
        simp [hz]
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem commitment_variable_candidate_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (p : PMF α) (encode : S → P → K)
    (decode : K → Option S)
    (prefixLaw : ∀ secret label, decode (encode secret label) = some secret)
    (labels : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) (fixed : Finset S) (q m : ℕ)
    (budget : ∀ program ∈ client.support,
      SelectedBudget (variableCandidate (publicDecode decode) fixed) program q)
    (candidates : R → Finset S)
    (count : ∀ value ∈ (privateIndependent p client).support, (candidates value).card ≤ m) :
    (commitmentGame (PMF.uniformOfFintype S) p encode client).toOuterMeasure
      (candidateEvent candidates) ≤ ((q + fixed.card + m : ℕ) : ℝ≥0∞) / Fintype.card S := by
  have queryBound : ((PMF.uniformOfFintype S).bind (privateGuess p decode client)) true ≤
      ((q + fixed.card : ℕ) : ℝ≥0∞) / Fintype.card S := by
    simpa only [privateGuess, secretPrelude, PMF.map_bind, PMF.map_comp, Function.comp_def] using
      secretPrelude_variable_bound (publicDecode decode) fixed p client (fun _ => none) q budget
  have bound := (commitment_candidate_comparison (PMF.uniformOfFintype S) p encode decode
    prefixLaw labels client candidates).trans (add_le_add
      (independent_candidate_bound (privateIndependent p client) candidates m count) queryBound)
  simpa only [← ENNReal.add_div, ← Nat.cast_add, Nat.add_comm m (q + fixed.card)] using bound

theorem opening_variable_candidate_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (decode : K → Option S) (project : H → S)
    (uniform : secretDraw.map project = PMF.uniformOfFintype S)
    (prefixLaw : ∀ secret label, decode (encode secret label) = some secret)
    (labels : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (OpeningProgram K P α H R n)) (fixed : Finset S) (q m : ℕ)
    (budget : ∀ program ∈ client.support,
      SelectedBudget (variableCandidate (publicDecode decode) fixed) (redactOpening program) q)
    (candidates : R → Finset S) (count : ∀ value, (candidates value).card ≤ m) :
    (openingGame secretDraw p encode project client).toOuterMeasure
      (candidateEvent (openingCandidates candidates)) ≤
        ((q + fixed.card + m : ℕ) : ℝ≥0∞) / Fintype.card S := by
  rw [opening_game_redaction, uniform]
  refine commitment_variable_candidate_bound p encode decode prefixLaw labels
    (client.map redactOpening) fixed q m ?_ (openingCandidates candidates) ?_
  · intro program supported
    rw [PMF.mem_support_map_iff] at supported
    obtain ⟨source, hs, rfl⟩ := supported
    exact budget source hs
  · intro value _
    exact opening_candidates_count candidates m count value

theorem opening_variable_candidate_bound_real [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (decode : K → Option S) (project : H → S)
    (uniform : secretDraw.map project = PMF.uniformOfFintype S)
    (prefixLaw : ∀ secret label, decode (encode secret label) = some secret)
    (labels : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (OpeningProgram K P α H R n)) (fixed : Finset S) (q m : ℕ)
    (budget : ∀ program ∈ client.support,
      SelectedBudget (variableCandidate (publicDecode decode) fixed) (redactOpening program) q)
    (candidates : R → Finset S) (count : ∀ value, (candidates value).card ≤ m) :
    ((openingGame secretDraw p encode project client).toOuterMeasure
      (candidateEvent (openingCandidates candidates))).toReal ≤
        (q + fixed.card + m : ℕ) / (Fintype.card S : ℝ) := by
  have bound := ENNReal.toReal_mono
    (show ((q + fixed.card + m : ℕ) : ℝ≥0∞) / Fintype.card S ≠ ⊤ by
      exact ENNReal.div_ne_top (by simp) (by simp))
    (opening_variable_candidate_bound secretDraw p encode decode project uniform prefixLaw labels
      client fixed q m budget candidates count)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast] using bound

end
end C10Probability
