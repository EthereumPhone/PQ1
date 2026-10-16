import C10Probability.PrivateQueries
import C10Probability.MemoRelabel

/-! Full interleaved public/private executions. The shared experiment relabels
private inputs through a single secret-prefixed memo table. The independent
experiment retains separate public/private sum-key entries. The stopped
interpreter is used only in the proof, never in either experiment below. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K P S α R : Type*}

theorem privateKey_good_injective [DecidableEq S] (encode : S → P → K)
    (decode : K → Option S) (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret)) (secret : S) :
    GoodInjective (privateKey encode secret) (privateBad decode secret) := by
  intro first second hfirst hsecond he
  cases first with
  | inl first =>
    cases second with
    | inl second => exact congrArg Sum.inl he
    | inr second =>
      have hn : decode first ≠ some secret := by
        simpa [privateBad, publicDecode] using hfirst
      exact False.elim (hn ((congrArg decode he).trans (prefixLaw secret second)))
  | inr first =>
    cases second with
    | inl second =>
      have hn : decode second ≠ some secret := by
        simpa [privateBad, publicDecode] using hsecond
      exact False.elim (hn ((congrArg decode he).symm.trans (prefixLaw secret first)))
    | inr second => exact congrArg Sum.inr (tails secret he)

def privateSharedAt [DecidableEq K] (p : PMF α) (encode : S → P → K) (secret : S)
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) : PMF R :=
  client.bind fun program =>
    (evalProgram p (mapProgram (privateKey encode secret) program) (fun _ => none)).map Prod.fst

def privateShared [DecidableEq K] (secretDraw : PMF S) (p : PMF α)
    (encode : S → P → K) {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) : PMF R :=
  secretDraw.bind fun secret => privateSharedAt p encode secret client

def privateIndependent [DecidableEq K] [DecidableEq P] (p : PMF α)
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) : PMF R :=
  (randomizedProgram p client (fun _ => none)).map Prod.fst

def privateGuess [DecidableEq K] [DecidableEq P] [DecidableEq S]
    (p : PMF α) (decode : K → Option S) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) (secret : S) : PMF Bool :=
  (randomizedTrace p client (fun _ => none)).map
    (fun out => prefixHit (publicDecode decode) (secret, out))

theorem private_program_bounds [DecidableEq K] [DecidableEq P] [DecidableEq S]
    (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret)) (secret : S)
    {n : ℕ} (program : QueryProgram (Sum K P) α R n) (event : Set R) :
    ((evalProgram p (mapProgram (privateKey encode secret) program) (fun _ => none)).map
        Prod.fst).toOuterMeasure event ≤
      ((evalProgram p program (fun _ => none)).map Prod.fst).toOuterMeasure event +
        ((traceProgram p program (fun _ => none)).map
          (fun out => prefixHit (publicDecode decode) (secret, out))) true ∧
    ((evalProgram p program (fun _ => none)).map Prod.fst).toOuterMeasure event ≤
      ((evalProgram p (mapProgram (privateKey encode secret) program) (fun _ => none)).map
        Prod.fst).toOuterMeasure event +
        ((traceProgram p program (fun _ => none)).map
          (fun out => prefixHit (publicDecode decode) (secret, out))) true := by
  simpa only [stoppedProgram_abort, privateBad_trace] using
    relabel_event_bounds p (privateKey encode secret) (privateBad decode secret)
      (privateKey_good_injective encode decode prefixLaw tails secret) program
      (fun _ => none) (fun _ => none)
      (tablesRelate_empty (privateKey encode secret) (privateBad decode secret)) event

theorem private_client_bounds [DecidableEq K] [DecidableEq P] [DecidableEq S]
    (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret)) (secret : S)
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) (event : Set R) :
    (privateSharedAt p encode secret client).toOuterMeasure event ≤
      (privateIndependent p client).toOuterMeasure event + privateGuess p decode client secret true ∧
    (privateIndependent p client).toOuterMeasure event ≤
      (privateSharedAt p encode secret client).toOuterMeasure event +
        privateGuess p decode client secret true := by
  let first := fun program : QueryProgram (Sum K P) α R n =>
    (evalProgram p (mapProgram (privateKey encode secret) program) (fun _ => none)).map Prod.fst
  let second := fun program : QueryProgram (Sum K P) α R n =>
    (evalProgram p program (fun _ => none)).map Prod.fst
  let charge := fun program : QueryProgram (Sum K P) α R n =>
    (traceProgram p program (fun _ => none)).map
      (fun out => prefixHit (publicDecode decode) (secret, out))
  have hl := mixture_charged_event_le client first second charge event
    (fun program => (private_program_bounds p encode decode prefixLaw tails secret program event).1)
  have hr := mixture_charged_event_le client second first charge event
    (fun program => (private_program_bounds p encode decode prefixLaw tails secret program event).2)
  simpa only [privateSharedAt, privateIndependent, privateGuess, randomizedProgram,
    randomizedTrace, PMF.map_bind, first, second, charge] using And.intro hl hr

theorem private_mixture_bounds [DecidableEq K] [DecidableEq P] [DecidableEq S]
    (secretDraw : PMF S) (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret))
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) (event : Set R) :
    (privateShared secretDraw p encode client).toOuterMeasure event ≤
      (privateIndependent p client).toOuterMeasure event +
        (secretDraw.bind (privateGuess p decode client)) true ∧
    (privateIndependent p client).toOuterMeasure event ≤
      (privateShared secretDraw p encode client).toOuterMeasure event +
        (secretDraw.bind (privateGuess p decode client)) true := by
  have hl := mixture_charged_event_le secretDraw
    (fun secret => privateSharedAt p encode secret client) (fun _ => privateIndependent p client)
    (privateGuess p decode client) event
    (fun secret => (private_client_bounds p encode decode prefixLaw tails secret client event).1)
  have hr := mixture_charged_event_le secretDraw
    (fun _ => privateIndependent p client) (fun secret => privateSharedAt p encode secret client)
    (privateGuess p decode client) event
    (fun secret => (private_client_bounds p encode decode prefixLaw tails secret client event).2)
  simpa only [privateShared, PMF.bind_const] using And.intro hl hr

theorem private_event_bounds [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret))
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q) (event : Set R) :
    (privateShared (PMF.uniformOfFintype S) p encode client).toOuterMeasure event ≤
      (privateIndependent p client).toOuterMeasure event + (q : ℝ≥0∞) / Fintype.card S ∧
    (privateIndependent p client).toOuterMeasure event ≤
      (privateShared (PMF.uniformOfFintype S) p encode client).toOuterMeasure event +
        (q : ℝ≥0∞) / Fintype.card S := by
  obtain ⟨hl, hr⟩ := private_mixture_bounds (PMF.uniformOfFintype S)
    p encode decode prefixLaw tails client event
  have hb : ((PMF.uniformOfFintype S).bind (privateGuess p decode client)) true ≤
      (q : ℝ≥0∞) / Fintype.card S := by
    simpa only [privateGuess, secretPrelude, PMF.map_bind, PMF.map_comp, Function.comp_def] using
      private_prefix_bound decode p client (fun _ => none) q budget
  exact ⟨hl.trans (add_le_add le_rfl hb), hr.trans (add_le_add le_rfl hb)⟩

theorem private_zero_public [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret))
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n))
    (budget : ∀ program ∈ client.support, PublicBudget program 0) :
    privateShared (PMF.uniformOfFintype S) p encode client = privateIndependent p client := by
  apply PMF.ext
  intro value
  obtain ⟨hl, hr⟩ := private_event_bounds p encode decode prefixLaw tails client 0 budget {value}
  exact le_antisymm
    (by simpa only [PMF.toOuterMeasure_apply_singleton, Nat.cast_zero, ENNReal.zero_div, add_zero] using hl)
    (by simpa only [PMF.toOuterMeasure_apply_singleton, Nat.cast_zero, ENNReal.zero_div, add_zero] using hr)

theorem private_event_error_real [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (p : PMF α) (encode : S → P → K) (decode : K → Option S)
    (prefixLaw : ∀ secret tail, decode (encode secret tail) = some secret)
    (tails : ∀ secret, Function.Injective (encode secret))
    {n : ℕ} (client : PMF (QueryProgram (Sum K P) α R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q) (event : Set R) :
    |((privateShared (PMF.uniformOfFintype S) p encode client).toOuterMeasure event).toReal -
      ((privateIndependent p client).toOuterMeasure event).toReal| ≤ (q : ℝ) / Fintype.card S := by
  obtain ⟨hl, hr⟩ := private_event_bounds p encode decode prefixLaw tails client q budget event
  have hd : (q : ℝ≥0∞) / Fintype.card S ≠ ⊤ := ENNReal.div_ne_top (by simp) (by simp)
  have hrealL := ENNReal.toReal_mono
    (ENNReal.add_ne_top.mpr ⟨event_mass_ne_top _ _, hd⟩) hl
  have hrealR := ENNReal.toReal_mono
    (ENNReal.add_ne_top.mpr ⟨event_mass_ne_top _ _, hd⟩) hr
  rw [ENNReal.toReal_add (event_mass_ne_top _ _) hd] at hrealL hrealR
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast] at hrealL hrealR
  exact abs_sub_le_iff.mpr ⟨by linarith, by linarith⟩

end
end C10Probability
