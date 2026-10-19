import C10Probability.ForestOpeningProvenance
import C10Probability.OpeningGrind

/-! A failed WOTS phase returns none without opening the deferred FORS node.
A successful signature opens it only when its secret array contains the
selected placeholder. The actual forest, two layers, result and cache agree. -/
namespace C10Probability
noncomputable section

theorem opening_avoids_cast {K P α H R : Type*} [DecidableEq K] (target : K)
    {n m : ℕ} (h : n = m) (program : OpeningProgram K P α H R n) :
    OpeningAvoids target (castOpening h program) = OpeningAvoids target program := by
  subst m
  rfl

theorem opening_avoids_reserve {K P α H R : Type*} [DecidableEq K] (target : K)
    (extra : ℕ) {n : ℕ} (program : OpeningProgram K P α H R n) :
    OpeningAvoids target (reserveOpening extra program) = OpeningAvoids target program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [reserveOpening, OpeningAvoids, ih]
  | commit label next ih => simp only [reserveOpening, OpeningAvoids, ih]
  | reveal next ih => simp only [reserveOpening, OpeningAvoids, ih]

theorem opening_avoids_bind {K P α H R T : Type*} [DecidableEq K] (target : K)
    {n m : ℕ} (program : OpeningProgram K P α H R n) (after : R → OpeningProgram K P α H T m)
    (first : OpeningAvoids target program) (later : ∀ value, OpeningAvoids target (after value)) :
    OpeningAvoids target (bindOpening program after) := by
  induction program with
  | done value =>
    simpa only [bindOpening, opening_avoids_cast, opening_avoids_reserve] using later value
  | query key next ih => exact ⟨first.1, fun reply => ih reply (first.2 reply)⟩
  | commit label next ih => exact fun reply => ih reply (first reply)
  | reveal next ih => exact fun secret => ih secret (first secret)

theorem opening_refines_bind_done {K P α U R S T : Type*} [DecidableEq K]
    (p : PMF α) (encode : U → P → K) (project : α → U) (target : K) (secret : α)
    (interpret : R → S) (finish : S → T) {n m a : ℕ}
    (instrumented : OpeningProgram K P α α R n) (ordinary : QueryProgram K α S m)
    (after : R → OpeningProgram K P α α T a)
    (first : OpeningRefines p encode project target secret interpret instrumented ordinary)
    (later : ∀ value, OpeningRefines p encode project target secret id
      (after value) (.done (n := 0) (finish (interpret value)))) :
    OpeningRefines p encode project target secret id (bindOpening instrumented after)
      (mapReturnProgram finish ordinary) := by
  have correspondence := opening_refines_bind p encode project target secret interpret id
    instrumented ordinary after (fun value => .done (n := 0) (finish value)) first later
  intro table opened cached
  simpa only [evalProgram_bind, evalProgram, evalProgram_mapReturn, PMF.map] using
    correspondence table opened cached

def c10ReleaseOpening (randomizer : Randomizer) (forest : DeferredForestOutput)
    (signed : HypertreeSigned) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Option C10Signature) 1 :=
  match signed with
  | none => .done none
  | some result => if none ∈ forest.secrets then
      .reveal (fun secret => .done (c10FinishOutput randomizer (deferredForestOutput secret forest) (some result)))
    else .done (c10FinishOutput randomizer (deferredForestOutput 0 forest) (some result))

def c10FinishOpening (target : ForsTarget) (seed : ByteKey) (randomizer : Randomizer)
    (digest : Digest) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    OpeningProgram WotsQuery ByteKey Digest Digest (Option C10Signature) (2 * n + 435045) :=
  castOpening (by omega) (bindOpening (forestSignOpening target seed (hypertreeIndex digest) digest shuffle)
    (fun forest => bindOpening
      (liftOpening (hypertreeSignProgram id seed shuffle n hb 2 0 (hypertreeIndex digest) forest.pk []))
      (c10ReleaseOpening randomizer forest)))

attribute [irreducible] c10FinishOpening

theorem c10_release_opening_refines (target : ForsTarget) (secret : Digest)
    (randomizer : Randomizer) (forest : DeferredForestOutput) (signed : HypertreeSigned) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (c10ReleaseOpening randomizer forest signed)
      (.done (n := 0) (c10FinishOutput randomizer (deferredForestOutput secret forest) signed)) := by
  intro table opened _
  cases signed with
  | none => simp only [c10ReleaseOpening, evalOpening, PMF.pure_map,
      openingProject, id_eq, evalProgram, c10FinishOutput, Option.map_none]
  | some result =>
    by_cases selected : none ∈ forest.secrets
    · simp only [c10ReleaseOpening, selected, ↓reduceIte, evalOpening, PMF.pure_map,
        openingProject, id_eq, evalProgram]
    · simp only [c10ReleaseOpening, selected, ↓reduceIte, evalOpening, PMF.pure_map,
        openingProject, id_eq, evalProgram, deferred_forest_known secret 0 forest selected]

theorem c10_finish_opening_refines (target : ForsTarget) (secret : Digest)
    (seed : ByteKey) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (c10FinishOpening target seed randomizer digest shuffle n hb)
      (c10FinishProgram id seed randomizer digest shuffle n hb) := by
  rw [c10FinishOpening, c10FinishProgram]
  apply opening_refines_cast
  apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret (deferredForestOutput secret) id _ _ _ _
    (forest_sign_opening_refines target secret seed (hypertreeIndex digest) digest shuffle)
  intro forest
  exact opening_refines_bind_done digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id (c10FinishOutput randomizer (deferredForestOutput secret forest)) _ _ _
    (opening_refines_lift digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret _)
    (c10_release_opening_refines target secret randomizer forest)

theorem c10_release_opening_avoids (target : ForsTarget) (randomizer : Randomizer)
    (forest : DeferredForestOutput) (signed : HypertreeSigned) :
    OpeningAvoids (forsTargetKey target) (c10ReleaseOpening randomizer forest signed) := by
  cases signed with
  | none => trivial
  | some result =>
    simp only [c10ReleaseOpening]
    split
    · exact fun _ => trivial
    · trivial

theorem c10_finish_opening_avoids (target : ForsTarget) (seed : ByteKey)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    OpeningAvoids (forsTargetKey target) (c10FinishOpening target seed randomizer digest shuffle n hb) := by
  rw [c10FinishOpening, opening_avoids_cast]
  apply opening_avoids_bind _ _ _
    (opening_sealed_avoids _ _ (forest_sign_opening_sealed target seed (hypertreeIndex digest) digest shuffle))
  intro forest
  exact opening_avoids_bind _ _ _ (opening_sealed_avoids _ _
    (query_exclusion_sealed _ _ (hypertree_sign_fors_excluded target seed shuffle n hb
      2 0 (hypertreeIndex digest) forest.pk []))) (c10_release_opening_avoids target randomizer forest)

theorem c10_release_opening_budget (randomizer : Randomizer) (forest : DeferredForestOutput)
    (signed : HypertreeSigned) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (c10ReleaseOpening randomizer forest signed)) 0 := by
  cases signed with
  | none => trivial
  | some result =>
    simp only [c10ReleaseOpening]
    split <;> trivial

theorem c10_finish_opening_budget (target : ForsTarget) (seed : ByteKey)
    (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (c10FinishOpening target seed randomizer digest shuffle n hb)) 408408 := by
  rw [c10FinishOpening, redact_opening_cast, selectedBudget_cast]
  apply opening_selected_bind _ _ _ 53386 355022
    (forest_sign_opening_budget target seed (hypertreeIndex digest) digest shuffle)
  intro forest
  exact opening_selected_bind _ _ _ 355022 0
    (opening_lift_variable_budget _ _ (hypertree_sign_variable_budget seed shuffle n hb
      2 0 (hypertreeIndex digest) forest.pk [])) (c10_release_opening_budget randomizer forest)

theorem c10_release_failure_retains (secret : Digest) (randomizer : Randomizer)
    (forest : DeferredForestOutput) (table : Memo WotsQuery Digest) (opened : Bool) :
    evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ReleaseOpening randomizer forest none) table opened = PMF.pure ⟨none, table, opened⟩ := by rfl

end
end C10Probability
