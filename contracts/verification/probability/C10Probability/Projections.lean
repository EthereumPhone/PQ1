import C10Probability.Grind
import Mathlib.Probability.Distributions.Uniform

/-!
# C10 acceptance projections

The WOTS projection is 43 base-eight digits with target sum 205. The FORS
acceptance projection is an eleven-bit field equal to zero. These are the
projection PMFs, not a Lean proof of their extraction from a 256-bit digest
or of fresh samples at every call of the persistent oracle. EasyCrypt proves
those distributional projections separately; that proof is not imported here.
-/

namespace C10Probability

open scoped ENNReal
noncomputable section

def signingBudget : ℕ := 10000000

abbrev WotsWord := Fin 43 → Fin 8

def wotsAccept (word : WotsWord) : Bool :=
  decide (∑ i, (word i).val = 205)

def wotsDraw : PMF WotsWord := PMF.uniformOfFintype WotsWord

abbrev AcceptedWots := {word : WotsWord // wotsAccept word = true}

/-- This is an exact finite cardinality, not an unproved numerical constant. -/
theorem wots_mass_count :
    acceptMass wotsDraw wotsAccept = (Nat.card AcceptedWots : ℝ≥0∞) / 8 ^ 43 := by
  rw [acceptMass_event, wotsDraw, PMF.toOuterMeasure_uniformOfFintype_apply]
  simp only [WotsWord, Fintype.card_fun, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat]
  simp only [Fintype.card_eq_nat_card]
  rfl

/-- 29 digits of seven, one digit of two, then thirteen zero digits. -/
def acceptedWotsWitness : WotsWord := fun i =>
  if i.val < 29 then 7 else if i.val = 29 then 2 else 0

theorem wots_acceptance_nonvacuous : wotsAccept acceptedWotsWitness = true := by decide

theorem wots_acceptance_not_total : wotsAccept (fun _ => 0) = false := by decide

theorem wots_mass_positive : 0 < acceptMass wotsDraw wotsAccept := by
  apply acceptMass_pos wotsDraw wotsAccept acceptedWotsWitness wots_acceptance_nonvacuous
  exact (wotsDraw.apply_pos_iff _).2 (PMF.mem_support_uniformOfFintype _)

theorem wots_mass_real :
    (acceptMass wotsDraw wotsAccept).toReal =
      (Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43 := by
  rw [wots_mass_count]
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow,
    ENNReal.toReal_ofNat]

theorem wots_exhaustion_real :
    (grind wotsDraw wotsAccept 0 signingBudget none).toReal =
      (1 - (Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) ^ signingBudget := by
  rw [grind_none_real, wots_mass_real]

theorem wots_atom_real (word : WotsWord) :
    (wotsDraw word).toReal = ((8 : ℝ) ^ 43)⁻¹ := by
  rw [wotsDraw, PMF.uniformOfFintype_apply]
  simp only [WotsWord, Fintype.card_fun, Fintype.card_fin, Nat.cast_pow,
    Nat.cast_ofNat, ENNReal.toReal_inv, ENNReal.toReal_pow, ENNReal.toReal_ofNat]

/-- Any accepted word at any valid first-hit counter has its exact probability. -/
theorem wots_first_hit (i : ℕ) (word : WotsWord) :
    (grind wotsDraw wotsAccept 0 signingBudget (some (i, word))).toReal =
      if i < signingBudget ∧ wotsAccept word = true
      then (1 - (Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) ^ i /
        (8 : ℝ) ^ 43 else 0 := by
  rw [grind_some_real, wots_mass_real, wots_atom_real]
  simp only [Nat.zero_le, zero_add, Nat.sub_zero, true_and, div_eq_mul_inv]

abbrev ForsField := Fin 2048

def forsAccept (field : ForsField) : Bool := decide (field = 0)

def forsDraw : PMF ForsField := PMF.uniformOfFintype ForsField

theorem fors_mass_exact : acceptMass forsDraw forsAccept = (2048 : ℝ≥0∞)⁻¹ := by
  simp [acceptMass, forsAccept, forsDraw]

theorem fors_acceptance_nonvacuous : forsAccept 0 = true := by decide

theorem fors_acceptance_not_total : forsAccept 1 = false := by decide

theorem fors_exhaustion_real :
    (grind forsDraw forsAccept 0 signingBudget none).toReal =
      (1 - (1 : ℝ) / 2048) ^ signingBudget := by
  rw [grind_none_real, fors_mass_exact]
  simp [one_div]

theorem fors_first_hit (i : ℕ) :
    (grind forsDraw forsAccept 0 signingBudget (some (i, 0))).toReal =
      if i < signingBudget then (1 - (1 : ℝ) / 2048) ^ i / 2048 else 0 := by
  rw [grind_some_real, fors_mass_exact]
  simp [forsDraw, forsAccept, div_eq_mul_inv]

end
end C10Probability
