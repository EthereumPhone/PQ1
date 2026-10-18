import C10Probability.ForsCoordinateLaw
import C10Probability.UniformSamples

/-! Fixed assignment of the twelve ordinary coordinates to independent
accepted witnesses. Every witness also matches the full hypertree address. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def forsGroupOpened {j : ℕ} (assignment : Fin 12 → Fin j) (group : Fin j)
    (target : Digest) (i : Fin 12) : Finset ForsField :=
  if assignment i = group then {(forsCoordinates target).2 i} else Finset.univ

def forsGroupEvent {j : ℕ} (assignment : Fin 12 → Fin j) (group : Fin j)
    (target : Digest) : Set Digest :=
  {d | forsCoordinates d ∈ forsCoordinateSet (forsCoordinates target).1
    (forsGroupOpened assignment group target)}

def forsGroupMass {j : ℕ} (assignment : Fin 12 → Fin j) (group : Fin j) : ℝ≥0∞ :=
  (∏ i, if assignment i = group then (2048 : ℝ≥0∞)⁻¹ else 1) / 2 ^ 18

theorem fors_group_event_coordinates {j : ℕ} (assignment : Fin 12 → Fin j)
    (group : Fin j) (target d : Digest) :
    d ∈ forsGroupEvent assignment group target ↔
      hypertreeIndex d = hypertreeIndex target ∧
        ∀ i, assignment i = group → forestIndex d i.val = forestIndex target i.val := by
  rw [forsGroupEvent, Set.mem_setOf_eq, fors_coordinate_set_member]
  simp only [forsGroupOpened]
  have address : (forsCoordinates d).1 = (forsCoordinates target).1 ↔
      hypertreeIndex d = hypertreeIndex target := by
    rw [← Fin.val_inj, fors_coordinates_address, fors_coordinates_address]
  rw [address]
  apply and_congr_right
  intro _
  apply forall_congr'
  intro i
  by_cases h : assignment i = group
  · simp only [h, ↓reduceIte, Finset.mem_singleton, true_implies]
    rw [← Fin.val_inj, fors_coordinates_index, fors_coordinates_index]
  · simp [h]

theorem accepted_fors_group_mass {j : ℕ} (assignment : Fin 12 → Fin j)
    (group : Fin j) (target : Digest) :
    acceptedForsDraw.toOuterMeasure (forsGroupEvent assignment group target) =
      forsGroupMass assignment group := by
  rw [forsGroupEvent, accepted_fors_coordinate_mass, forsGroupMass]
  have factors : (∏ i, if assignment i = group then (2048 : ℝ≥0∞)⁻¹ else 1) =
      ∏ i, ((forsGroupOpened assignment group target i).card : ℝ≥0∞) / 2048 := by
    apply Finset.prod_congr rfl
    intro i _
    by_cases h : assignment i = group <;>
      norm_num [forsGroupOpened, h, ForsField, ENNReal.div_self]
  rw [factors, ENNReal.prod_div_distrib_of_ne_top (by simp)]
  simp only [Finset.prod_const, Finset.card_univ, Fintype.card_fin]
  simp only [div_eq_mul_inv]
  rw [ENNReal.mul_inv (Or.inl (by simp)) (Or.inl (by simp))]
  ring

theorem fors_assignment_product_mass {j : ℕ} (assignment : Fin 12 → Fin j) :
    (∏ group, forsGroupMass assignment group) = ((2 : ℝ≥0∞) ^ (132 + 18 * j))⁻¹ := by
  simp only [forsGroupMass]
  rw [ENNReal.prod_div_distrib_of_ne_top (by simp), Finset.prod_comm]
  have one : ∀ i : Fin 12,
      (∏ group : Fin j, if assignment i = group then (2048 : ℝ≥0∞)⁻¹ else 1) =
        (2048 : ℝ≥0∞)⁻¹ := by
    intro i
    simp
  simp_rw [one]
  simp only [Finset.prod_const, Finset.card_univ, Fintype.card_fin]
  rw [← ENNReal.inv_pow, div_eq_mul_inv,
    ← ENNReal.mul_inv (Or.inl (by norm_num)) (Or.inl (by simp))]
  congr 1
  rw [show (2048 : ℝ≥0∞) ^ 12 = 2 ^ 132 by norm_num, ← pow_mul, ← pow_add]

end
end C10Probability
