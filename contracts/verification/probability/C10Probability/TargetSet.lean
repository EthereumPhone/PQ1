import C10Probability.TargetEvent
import C10Probability.AdaptiveCollision

/-! A fixed projected target set. Only fresh reply projections are uniform;
the query keys can depend on every earlier reply. Targets are not postselected. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K α V R : Type*} [DecidableEq K] [DecidableEq V] [Fintype V] [Nonempty V]

def inTargets (project : α → V) (targets : Finset V) (value : α) : Bool :=
  decide (project value ∈ targets)

theorem projected_target_mass (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) (targets : Finset V) :
    acceptMass p (inTargets project targets) =
      (targets.card : ℝ≥0∞) / Fintype.card V := by
  simpa only [acceptMass, inTargets, decide_eq_true_eq, mul_ite, mul_one, mul_zero] using
    projected_seen_mass p project hu targets

theorem randomizedProgram_target_set_bound (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) (targets : Finset V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α)
    (h : NoTarget (inTargets project targets) table) :
    (randomizedProgram p client table).toOuterMeasure
      {out | ¬ NoTarget (inTargets project targets) out.2} ≤
        (n : ℝ≥0∞) * targets.card / Fintype.card V := by
  simpa only [projected_target_mass p project hu targets, mul_div_assoc] using
    randomizedProgram_target_bound p (inTargets project targets) client table h

theorem randomizedProgram_target_set_bound_real (p : PMF α) (project : α → V)
    (hu : p.map project = PMF.uniformOfFintype V) (targets : Finset V) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α)
    (h : NoTarget (inTargets project targets) table) :
    ((randomizedProgram p client table).toOuterMeasure
      {out | ¬ NoTarget (inTargets project targets) out.2}).toReal ≤
        (n : ℝ) * targets.card / Fintype.card V := by
  simpa only [projected_target_mass p project hu targets, ENNReal.toReal_div,
    ENNReal.toReal_natCast, mul_div_assoc] using
      randomizedProgram_target_bound_real p (inTargets project targets) client table h

end
end C10Probability
