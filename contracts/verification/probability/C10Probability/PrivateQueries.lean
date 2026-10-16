import C10Probability.QueryMap
import C10Probability.PrefixGuess

/-! Public/private calls share the existing adaptive program representation. The ideal
oracle uses sum-key memo entries: private replies may influence all subsequent
queries, but neither its program nor its initial randomness receives the secret.
Only public calls contribute candidates to the private-prefix guess. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K P S α R : Type*}

def publicDecode (decode : K → Option S) : Sum K P → Option S
  | .inl key => decode key
  | .inr _ => none

def privateKey (encode : S → P → K) (secret : S) : Sum K P → K
  | .inl key => key
  | .inr tail => encode secret tail

def privateBad [DecidableEq S] (decode : K → Option S) (secret : S)
    (key : Sum K P) : Bool := decide (publicDecode decode key = some secret)

theorem publicCandidates_eq [DecidableEq S] (decode : K → Option S)
    (queries : List (Sum K P)) :
    prefixCandidates (publicDecode decode) queries =
      prefixCandidates decode (publicQueries queries) := by
  unfold prefixCandidates
  congr 1
  induction queries with
  | nil => rfl
  | cons key rest ih =>
    cases key with
    | inl key =>
      cases hd : decode key <;>
        simpa only [publicDecode, publicQueries, List.filterMap_cons, hd,
          List.cons.injEq, true_and] using ih
    | inr tail =>
      simpa only [publicDecode, publicQueries, List.filterMap_cons] using ih

theorem publicCandidates_card_le [DecidableEq S] (decode : K → Option S)
    (queries : List (Sum K P)) :
    (prefixCandidates (publicDecode decode) queries).card ≤ (publicQueries queries).length := by
  rw [publicCandidates_eq]
  exact prefixCandidates_card_le decode (publicQueries queries)

theorem privateBad_trace [DecidableEq S] (decode : K → Option S) (secret : S)
    (out : TraceOutput (Sum K P) α R) :
    out.queries.any (privateBad decode secret) = prefixHit (publicDecode decode) (secret, out) := by
  apply Bool.eq_iff_iff.mpr
  simp [privateBad, prefixHit, prefixCandidates_mem, List.any_eq_true]

theorem private_prefix_bound [Fintype S] [Nonempty S] [DecidableEq S]
    [DecidableEq K] [DecidableEq P] (decode : K → Option S) (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram (Sum K P) α R n)) (table : Memo (Sum K P) α) (q : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q) :
    ((secretPrelude (PMF.uniformOfFintype S) p client table).map
      (prefixHit (publicDecode decode))) true ≤ (q : ℝ≥0∞) / Fintype.card S := by
  rw [secretPrelude_late, PMF.map_bind, PMF.bind_apply]
  simp only [PMF.map_comp, Function.comp_def, prefixHit, uniform_prefix_mass]
  calc
    _ ≤ ∑' out, (randomizedTrace p client table) out *
        ((q : ℝ≥0∞) / Fintype.card S) := by
      apply ENNReal.tsum_le_tsum
      intro out
      by_cases hs : out ∈ (randomizedTrace p client table).support
      · apply mul_le_mul_right
        apply ENNReal.div_le_div_right
        exact_mod_cast (publicCandidates_card_le decode out.queries).trans
          (randomizedTrace_public_length p client q budget table out hs)
      · have hz := (PMF.apply_eq_zero_iff _ out).mpr hs
        simp [hz]
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

end
end C10Probability
