import C10Probability.StoppedProgram

/-! Cache correspondence for a key map that is injective away from designated
bad queries. This permits a physical cache to identify a public and a private
input only in the explicitly charged bad-query domain. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K L α R : Type*}

def GoodInjective (encode : K → L) (bad : K → Bool) : Prop :=
  ∀ first second, bad first = false → bad second = false →
    encode first = encode second → first = second

def TablesRelate (encode : K → L) (bad : K → Bool)
    (physical : Memo L α) (ideal : Memo K α) : Prop :=
  ∀ key, bad key = false → physical (encode key) = ideal key

theorem tablesRelate_empty (encode : K → L) (bad : K → Bool) :
    TablesRelate encode bad (fun _ => (none : Option α)) (fun _ => none) := by
  intro key _
  rfl

theorem tablesRelate_update [DecidableEq K] [DecidableEq L] (encode : K → L) (bad : K → Bool)
    (injective : GoodInjective encode bad) (physical : Memo L α) (ideal : Memo K α)
    (related : TablesRelate encode bad physical ideal) (key : K) (good : bad key = false)
    (reply : α) :
    TablesRelate encode bad (Function.update physical (encode key) (some reply))
      (Function.update ideal key (some reply)) := by
  intro other hother
  by_cases he : other = key
  · subst other
    simp
  · have hn : encode other ≠ encode key :=
      fun h => he (injective other key hother good h)
    simpa [he, hn] using related other hother

theorem stoppedProgram_relabel [DecidableEq K] [DecidableEq L] (p : PMF α) (encode : K → L) (bad : K → Bool)
    (injective : GoodInjective encode bad) {n : ℕ} (program : QueryProgram K α R n)
    (physical : Memo L α) (ideal : Memo K α)
    (related : TablesRelate encode bad physical ideal) :
    stoppedProgram p encode bad program physical = stoppedProgram p id bad program ideal := by
  induction program generalizing physical ideal with
  | done value => rfl
  | query key next ih =>
    cases hb : bad key
    · have hr := related key hb
      cases hc : ideal key with
      | none =>
        have hp : physical (encode key) = none := hr.trans hc
        simp only [stoppedProgram, hb, Bool.false_eq_true, ↓reduceIte, id_eq,
          memoQuery, hp, hc, PMF.bind_map, Function.comp_def]
        congr 1
        funext reply
        exact ih reply _ _ (tablesRelate_update encode bad injective physical ideal
          related key hb reply)
      | some reply =>
        have hp : physical (encode key) = some reply := hr.trans hc
        simpa only [stoppedProgram, hb, Bool.false_eq_true, ↓reduceIte, id_eq,
          memoQuery, hp, hc, PMF.pure_bind] using ih reply physical ideal related
    · simp [stoppedProgram, hb]

theorem relabel_event_bounds [DecidableEq K] [DecidableEq L] (p : PMF α) (encode : K → L) (bad : K → Bool)
    (injective : GoodInjective encode bad) {n : ℕ} (program : QueryProgram K α R n)
    (physical : Memo L α) (ideal : Memo K α)
    (related : TablesRelate encode bad physical ideal) (event : Set R) :
    ((evalProgram p (mapProgram encode program) physical).map Prod.fst).toOuterMeasure event ≤
        ((evalProgram p program ideal).map Prod.fst).toOuterMeasure event +
          stoppedProgram p id bad program ideal none ∧
    ((evalProgram p program ideal).map Prod.fst).toOuterMeasure event ≤
        ((evalProgram p (mapProgram encode program) physical).map Prod.fst).toOuterMeasure event +
          stoppedProgram p id bad program ideal none := by
  have he := stoppedProgram_relabel p encode bad injective program physical ideal related
  have hl := fullProgram_event_charge p encode bad program physical event
  rw [he] at hl
  have hi := stoppedProgram_retained_le p id bad program ideal event
  simp only [mapProgram_id] at hi
  have hr := fullProgram_event_charge p id bad program ideal event
  simp only [mapProgram_id] at hr
  have hp := stoppedProgram_retained_le p encode bad program physical event
  rw [he] at hp
  exact ⟨hl.trans (add_le_add hi le_rfl), hr.trans (add_le_add hp le_rfl)⟩

theorem mixture_charged_event_le {β : Type*} (mix : PMF β)
    (first second : β → PMF R) (charge : β → PMF Bool) (event : Set R)
    (bound : ∀ index, (first index).toOuterMeasure event ≤
      (second index).toOuterMeasure event + charge index true) :
    (mix.bind first).toOuterMeasure event ≤
      (mix.bind second).toOuterMeasure event + (mix.bind charge) true := by
  rw [PMF.toOuterMeasure_bind_apply, PMF.toOuterMeasure_bind_apply,
    PMF.bind_apply, ← ENNReal.tsum_add]
  apply ENNReal.tsum_le_tsum
  intro index
  simpa only [mul_add] using mul_le_mul_right (bound index) (mix index)

end
end C10Probability
