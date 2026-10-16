import C10Probability.SelectedCollision
import C10Probability.NodeDomain
import C10Probability.NodeCharges

/-! The refined node charge narrows only the collision event. Zero nodes
anywhere in the full raw cache still consume the full total-call allowance. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def DomainNodeBad (table : Memo ByteKey Digest) : Prop :=
  (¬ CollisionFree randomizerOfDigest (selectedCache nodeQuery table)) ∨ PublicNodeZero table

theorem digest_program_domain_collision_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget nodeQuery program q) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree randomizerOfDigest (selectedCache nodeQuery out.2)} ≤
        (q.choose 2 : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  simpa only [Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
    randomizedProgram_selected_empty_bound digestDraw nodeQuery randomizerOfDigest
      randomizer_uniform client q budget

theorem digest_program_domain_node_bad_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget nodeQuery program q) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | DomainNodeBad out.2} ≤
        ((q.choose 2 + n : ℕ) : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  have hu := MeasureTheory.measure_union_le
    (μ := (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure)
    {out | ¬ CollisionFree randomizerOfDigest (selectedCache nodeQuery out.2)}
    {out | PublicNodeZero out.2}
  exact hu.trans (by
    simpa only [← ENNReal.add_div, ← Nat.cast_add] using
      add_le_add (digest_program_domain_collision_bound client q budget)
        (digest_program_zero_bound client))

theorem digest_program_domain_node_bad_bound_real {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget nodeQuery program q) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | DomainNodeBad out.2}).toReal ≤
        ((q.choose 2 + n : ℕ) : ℝ) / (2 : ℝ) ^ 128 := by
  have h := ENNReal.toReal_mono (show
      ((q.choose 2 + n : ℕ) : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 ≠ ⊤ by
        exact ENNReal.div_ne_top (by simp) (by simp))
    (digest_program_domain_node_bad_bound client q budget)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat] using h

end
end C10Probability
