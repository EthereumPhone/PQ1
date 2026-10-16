import C10Probability.NodeZero

/-! The collision and zero-sentinel events share the same actual adaptive
program and final cache. This is a two-event union, not full forgery composition. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def PublicNodeBad (table : Memo ByteKey Digest) : Prop :=
  (¬ CollisionFree randomizerOfDigest table) ∨ PublicNodeZero table

theorem digest_program_node_bad_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | PublicNodeBad out.2} ≤
        ((n.choose 2 + n : ℕ) : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  have hc : (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ CollisionFree randomizerOfDigest out.2} ≤
        (n.choose 2 : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
    simpa only [emptyView, Finset.card_empty, collisionPairs, Nat.mul_zero, Nat.zero_add,
      Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
        randomizedProgram_collision_bound digestDraw randomizerOfDigest randomizer_uniform
          client emptyView (emptyView_valid randomizerOfDigest) rfl
  have hu := MeasureTheory.measure_union_le
    (μ := (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure)
    {out | ¬ CollisionFree randomizerOfDigest out.2} {out | PublicNodeZero out.2}
  exact hu.trans (by
    simpa only [← ENNReal.add_div, ← Nat.cast_add] using
      add_le_add hc (digest_program_zero_bound client))

theorem digest_program_node_bad_bound_real {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | PublicNodeBad out.2}).toReal ≤
        ((n.choose 2 + n : ℕ) : ℝ) / (2 : ℝ) ^ 128 := by
  have h := ENNReal.toReal_mono (show
      ((n.choose 2 + n : ℕ) : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 ≠ ⊤ by
        exact ENNReal.div_ne_top (by simp) (by simp)) (digest_program_node_bad_bound client)
  simpa only [ENNReal.toReal_div, ENNReal.toReal_natCast,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat] using h

end
end C10Probability
