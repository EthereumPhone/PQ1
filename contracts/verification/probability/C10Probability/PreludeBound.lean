import C10Probability.PreludeTransfer

/-! The first-call exhaustion bound composes public history, the memoized
randomizer collision charge and the independently derived prefix charge.
Both query counts are worst-case bounds; neither is expected grinding work. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K R α β : Type*}

theorem public_trace_history_card [Fintype K] [DecidableEq K] {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q))
    (out : TraceOutput ByteKey Digest R)
    (ho : out ∈ (randomizedTrace digestDraw client (fun _ => none)).support)
    (embed : K → ByteKey) (hi : Function.Injective embed) :
    (embeddedHistory out.cache embed).card ≤ q := by
  have hsub : (embeddedHistory out.cache embed).image embed ⊆ out.queries.toFinset := by
    intro key hk
    obtain ⟨source, hs, rfl⟩ := Finset.mem_image.mp hk
    cases hc : out.cache (embed source) with
    | none => simp [embeddedHistory, hc] at hs
    | some value =>
      exact List.mem_toFinset.mpr (randomizedTrace_empty_covered digestDraw client out ho
        (embed source) value hc)
  calc
    _ = ((embeddedHistory out.cache embed).image embed).card :=
      (Finset.card_image_of_injective _ hi).symm
    _ ≤ out.queries.toFinset.card := Finset.card_le_card hsub
    _ ≤ out.queries.length := List.toFinset_card_le out.queries
    _ ≤ q := randomizedTrace_length digestDraw client (fun _ => none) out ho

theorem mixture_event_bound_real (p : PMF β) (f : β → PMF α) (event : Set α)
    (bound : ℝ) (hb : 0 ≤ bound)
    (h : ∀ value ∈ p.support, ((f value).toOuterMeasure event).toReal ≤ bound) :
    ((p.bind f).toOuterMeasure event).toReal ≤ bound := by
  have he : (p.bind f).toOuterMeasure event ≤ ENNReal.ofReal bound := by
    rw [PMF.toOuterMeasure_bind_apply]
    calc
      _ ≤ ∑' value, p value * ENNReal.ofReal bound := by
        apply ENNReal.tsum_le_tsum
        intro value
        by_cases hs : value ∈ p.support
        · exact mul_le_mul_right
            ((ENNReal.le_ofReal_iff_toReal_le (event_mass_ne_top _ _) hb).mpr (h value hs)) _
        · have hz := (p.apply_eq_zero_iff value).mpr hs
          simp [hz]
      _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
  simpa only [ENNReal.toReal_ofReal hb] using ENNReal.toReal_mono ENNReal.ofReal_ne_top he

theorem preludeIndependent_exhaustion {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest) (n : ℕ) :
    ((preludeIndependent client request n).toOuterMeasure {out | out.2 = none}).toReal ≤
      (1 - (1 : ℝ) / 2048) ^ n + (collisionPairs q n : ℝ) / (2 : ℝ) ^ 128 := by
  have hb : 0 ≤ (1 - (1 : ℝ) / 2048) ^ n +
      (collisionPairs q n : ℝ) / (2 : ℝ) ^ 128 := by positivity
  apply mixture_event_bound_real _ _ _ _ hb
  intro prior hp
  rw [PMF.toOuterMeasure_map_apply]
  have hm : (randomizerMemoSearch prior.cache (request prior.value).seed
      (request prior.value).root (request prior.value).message n).toOuterMeasure
        {out | out.1 = none} =
      ((randomizerMemoSearch prior.cache (request prior.value).seed
        (request prior.value).root (request prior.value).message n).map Prod.fst) none := by
    rw [← PMF.toOuterMeasure_apply_singleton, PMF.toOuterMeasure_map_apply]
    rfl
  change ((randomizerMemoSearch prior.cache (request prior.value).seed
    (request prior.value).root (request prior.value).message n).toOuterMeasure
      {out | out.1 = none}).toReal ≤ _
  rw [hm]
  have hmass := (abs_le.mp (fors_memo_exhaustion_error prior.cache
    (request prior.value).seed (request prior.value).root (request prior.value).message n)).2
  have hcard := public_trace_history_card client prior hp
    (hmsgRandomizerInput (request prior.value).seed (request prior.value).root
      (request prior.value).message)
    (hmsg_randomizer_injective _ _ _)
  have hnat := collision_pairs_mono_history _ q n hcard
  have hcast : (collisionPairs
      (embeddedHistory prior.cache (hmsgRandomizerInput (request prior.value).seed
        (request prior.value).root (request prior.value).message)).card n : ℝ) ≤
        (collisionPairs q n : ℝ) := by exact_mod_cast hnat
  have hdiv := div_le_div_of_nonneg_right hcast (by positivity : 0 ≤ (2 : ℝ) ^ 128)
  linarith

theorem preludeShared_exhaustion {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest)
    (hv : ∀ value, RequestValid (request value)) (n : ℕ) (hb : 0 + n ≤ 2 ^ 32) :
    ((preludeShared client request n hb).toOuterMeasure {out | out.2 = none}).toReal ≤
      (1 - (1 : ℝ) / 2048) ^ n + (collisionPairs q n : ℝ) / (2 : ℝ) ^ 128 +
        (q : ℝ) / (2 : ℝ) ^ 256 := by
  have htransfer := (abs_le.mp (prelude_event_error_real client request hv n hb
    {out | out.2 = none})).2
  have hind := preludeIndependent_exhaustion client request n
  linarith

theorem preludeShared_signing_exhaustion {q : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R q)) (request : R → GrindRequest)
    (hv : ∀ value, RequestValid (request value)) :
    ((preludeShared client request signingBudget signing_counter_fits).toOuterMeasure
      {out | out.2 = none}).toReal ≤
        (1 - (1 : ℝ) / 2048) ^ signingBudget +
          (collisionPairs q signingBudget : ℝ) / (2 : ℝ) ^ 128 +
            (q : ℝ) / (2 : ℝ) ^ 256 := by
  exact preludeShared_exhaustion client request hv signingBudget signing_counter_fits

end
end C10Probability
