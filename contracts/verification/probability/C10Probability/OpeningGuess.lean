import C10Probability.OpeningProgram

/-! Adaptive reveals are removed only from the unopened-candidate event.
The secret may contain more information than its uniformly projected node;
the real reveal returns that complete secret. Redaction makes the comparison
depend only on the projected node without assuming transcript independence. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K P α H S R : Type*}

def openingGame [DecidableEq K] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (project : H → S) {n : ℕ}
    (client : PMF (OpeningProgram K P α H R n)) : PMF (S × Option R) :=
  secretDraw.bind fun secret => client.bind fun program =>
    (evalOpening p encode project secret program (fun _ => none) false).map
      fun out => (project secret, openingRetain out)

def openingCandidates (candidates : R → Finset S) : Option R → Finset S
  | none => ∅
  | some value => candidates value

theorem opening_game_redaction [DecidableEq K] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (project : H → S) {n : ℕ}
    (client : PMF (OpeningProgram K P α H R n)) :
    openingGame secretDraw p encode project client =
      commitmentGame (secretDraw.map project) p encode (client.map redactOpening) := by
  simp only [openingGame, commitmentGame, privateSharedAt, PMF.bind_map, PMF.map_bind]
  congr 1
  funext secret
  congr 1
  funext program
  have redaction := congrArg (fun result : PMF (Option R) =>
    result.map (fun value => (project secret, value)))
    (eval_opening_redaction p encode project secret program (fun _ => none))
  simpa only [PMF.map_comp, Function.comp_def] using redaction

theorem opening_candidates_count (candidates : R → Finset S) (m : ℕ)
    (bound : ∀ value, (candidates value).card ≤ m) (out : Option R) :
    (openingCandidates candidates out).card ≤ m := by
  cases out with
  | none => simp only [openingCandidates, Finset.card_empty, Nat.zero_le]
  | some value => exact bound value

theorem opening_candidate_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (decode : K → Option S) (project : H → S)
    (uniform : secretDraw.map project = PMF.uniformOfFintype S)
    (prefixLaw : ∀ secret label, decode (encode secret label) = some secret)
    (labels : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (OpeningProgram K P α H R n)) (q m : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget (redactOpening program) q)
    (candidates : R → Finset S) (count : ∀ value, (candidates value).card ≤ m) :
    (openingGame secretDraw p encode project client).toOuterMeasure
      (candidateEvent (openingCandidates candidates)) ≤
        ((q + m : ℕ) : ℝ≥0∞) / Fintype.card S := by
  rw [opening_game_redaction, uniform]
  refine commitment_candidate_bound p encode decode prefixLaw labels
    (client.map redactOpening) q m ?_ (openingCandidates candidates) ?_
  · intro program supported
    rw [PMF.mem_support_map_iff] at supported
    obtain ⟨source, hs, rfl⟩ := supported
    exact budget source hs
  · intro value _
    exact opening_candidates_count candidates m count value

theorem opening_candidate_bound_real [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (decode : K → Option S) (project : H → S)
    (uniform : secretDraw.map project = PMF.uniformOfFintype S)
    (prefixLaw : ∀ secret label, decode (encode secret label) = some secret)
    (labels : ∀ secret, Function.Injective (encode secret)) {n : ℕ}
    (client : PMF (OpeningProgram K P α H R n)) (q m : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget (redactOpening program) q)
    (candidates : R → Finset S) (count : ∀ value, (candidates value).card ≤ m) :
    ((openingGame secretDraw p encode project client).toOuterMeasure
      (candidateEvent (openingCandidates candidates))).toReal ≤
        (q + m : ℕ) / (Fintype.card S : ℝ) := by
  have bound := ENNReal.toReal_mono
    (show ((q + m : ℕ) : ℝ≥0∞) / Fintype.card S ≠ ⊤ by
      exact ENNReal.div_ne_top (by simp) (by simp))
    (opening_candidate_bound secretDraw p encode decode project uniform prefixLaw labels
      client q m budget candidates count)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast] using bound

theorem opening_reveal_no_candidate [DecidableEq K] (secretDraw : PMF H) (p : PMF α)
    (encode : S → P → K) (project : H → S) {n : ℕ}
    (next : H → OpeningProgram K P α H R n) (candidates : R → Finset S) :
    (openingGame secretDraw p encode project (PMF.pure (.reveal next))).toOuterMeasure
      (candidateEvent (openingCandidates candidates)) = 0 := by
  rw [opening_game_redaction]
  simp only [PMF.pure_map, redactOpening, commitmentGame, privateSharedAt,
    PMF.pure_bind, mapProgram, evalProgram, PMF.pure_map]
  simp [PMF.toOuterMeasure_bind_apply, PMF.toOuterMeasure_pure_apply,
    candidateEvent, openingCandidates]

end
end C10Probability
