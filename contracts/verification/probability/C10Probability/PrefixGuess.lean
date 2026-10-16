import C10Probability.QueryTrace
import C10Probability.AdaptiveCollision

/-! Independent hidden-secret guessing in an actual adaptive public prelude.
The secret is sampled first, but is not supplied to the client, its random
program, the initial table or the reply distribution. No claim is made for a
transcript that already exposes information depending on that secret. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α R S : Type*}

def prefixCandidates [DecidableEq S] (decode : K → Option S) (queries : List K) : Finset S :=
  (queries.filterMap decode).toFinset

theorem prefixCandidates_mem [DecidableEq S] (decode : K → Option S) (queries : List K) (secret : S) :
    secret ∈ prefixCandidates decode queries ↔ ∃ key ∈ queries, decode key = some secret := by
  simp [prefixCandidates]

theorem prefixCandidates_card_le [DecidableEq S] (decode : K → Option S) (queries : List K) :
    (prefixCandidates decode queries).card ≤ queries.length := by
  exact (List.toFinset_card_le (l := queries.filterMap decode)).trans (List.length_filterMap_le _ _)

def secretPrelude [DecidableEq K] (secretDraw : PMF S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) :
    PMF (S × TraceOutput K α R) :=
  secretDraw.bind fun secret =>
    (randomizedTrace p client table).map fun out => (secret, out)

def prefixHit [DecidableEq S] (decode : K → Option S) (out : S × TraceOutput K α R) : Bool :=
  decide (out.1 ∈ prefixCandidates decode out.2.queries)

theorem secretPrelude_late [DecidableEq K] (secretDraw : PMF S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) :
    secretPrelude secretDraw p client table =
      (randomizedTrace p client table).bind fun out =>
        secretDraw.map fun secret => (secret, out) := by
  exact PMF.bind_comm secretDraw (randomizedTrace p client table)
    (fun secret out => PMF.pure (secret, out))

theorem secretPrelude_public [DecidableEq K] (secretDraw : PMF S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) :
    (secretPrelude secretDraw p client table).map Prod.snd = randomizedTrace p client table := by
  simpa only [secretPrelude, PMF.map_bind, PMF.map_comp, Function.comp_def, PMF.bind_const] using
    PMF.map_id (randomizedTrace p client table)

theorem secretPrelude_support [DecidableEq K] (secretDraw : PMF S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α)
    (out : S × TraceOutput K α R)
    (ho : out ∈ (secretPrelude secretDraw p client table).support) :
    out.2 ∈ (randomizedTrace p client table).support := by
  rw [secretPrelude, PMF.mem_support_bind_iff] at ho
  obtain ⟨secret, _, ho⟩ := ho
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨trace, ht, rfl⟩ := ho
  exact ht

theorem prefixHit_false_fresh [DecidableEq K] [DecidableEq S] (decode : K → Option S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (out : S × TraceOutput K α R)
    (ho : out.2 ∈ (randomizedTrace p client (fun _ => none)).support)
    (hb : prefixHit decode out = false) (key : K) (hk : decode key = some out.1) :
    out.2.cache key = none := by
  cases hc : out.2.cache key with
  | none => rfl
  | some value =>
    have hm := randomizedTrace_empty_covered p client out.2 ho key value hc
    have hs : out.1 ∈ prefixCandidates decode out.2.queries :=
      (prefixCandidates_mem decode out.2.queries out.1).mpr ⟨key, hm, hk⟩
    simp [prefixHit, hs] at hb

variable [Fintype S] [Nonempty S]

theorem uniform_prefix_mass [DecidableEq S] (decode : K → Option S) (queries : List K) :
    ((PMF.uniformOfFintype S).map
      (fun secret => decide (secret ∈ prefixCandidates decode queries))) true =
        ((prefixCandidates decode queries).card : ℝ≥0∞) / Fintype.card S := by
  simpa [PMF.map_apply] using uniform_seen_mass (prefixCandidates decode queries)

theorem secretPrelude_prefix_bound [DecidableEq K] [DecidableEq S] (decode : K → Option S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) :
    ((secretPrelude (PMF.uniformOfFintype S) p client table).map (prefixHit decode)) true ≤
      (n : ℝ≥0∞) / Fintype.card S := by
  rw [secretPrelude_late, PMF.map_bind, PMF.bind_apply]
  simp only [PMF.map_comp, Function.comp_def, prefixHit, uniform_prefix_mass]
  calc
    _ ≤ ∑' out, (randomizedTrace p client table) out *
        ((n : ℝ≥0∞) / Fintype.card S) := by
      apply ENNReal.tsum_le_tsum
      intro out
      by_cases hs : out ∈ (randomizedTrace p client table).support
      · apply mul_le_mul_right
        apply ENNReal.div_le_div_right
        exact_mod_cast (prefixCandidates_card_le decode out.queries).trans
          (randomizedTrace_length p client table out hs)
      · have hz := (PMF.apply_eq_zero_iff _ out).mpr hs
        simp [hz]
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem secretPrelude_prefix_bound_real [DecidableEq K] [DecidableEq S] (decode : K → Option S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) :
    (((secretPrelude (PMF.uniformOfFintype S) p client table).map
      (prefixHit decode)) true).toReal ≤ (n : ℝ) / Fintype.card S := by
  have h := ENNReal.toReal_mono (show (n : ℝ≥0∞) / Fintype.card S ≠ ⊤ by
    exact ENNReal.div_ne_top (by simp) (by simp))
    (secretPrelude_prefix_bound decode p client table)
  simpa using h

end
end C10Probability
