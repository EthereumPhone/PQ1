import C10Probability.Digest
import C10Probability.Returned

/-! Transfer through a projection, without dropping failure or the first-hit index. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {α β : Type*}

def projectResult (f : α → β) : Option (ℕ × α) → Option (ℕ × β) :=
  Option.map (Prod.map id f)

theorem project_none (f : α → β) : projectResult f none = none := by rfl

theorem project_some (f : α → β) (i : ℕ) (x : α) :
    projectResult f (some (i, x)) = some (i, f x) := by rfl

theorem grind_projection (p : PMF α) (f : α → β) (accept : β → Bool)
    (start n : ℕ) :
    (grind p (accept ∘ f) start n).map (projectResult f) =
      grind (p.map f) accept start n := by
  induction n generalizing start with
  | zero => simp [grind, PMF.pure_map, projectResult]
  | succ n ih =>
    simp only [grind, PMF.map_bind, PMF.bind_map, Function.comp_def]
    apply congrArg (PMF.bind p)
    funext x
    cases accept (f x) with
    | false => exact ih (start + 1)
    | true => simp [PMF.pure_map, projectResult]

theorem acceptMass_projection (p : PMF α) (f : α → β) (accept : β → Bool) :
    acceptMass p (accept ∘ f) = acceptMass (p.map f) accept := by
  simp [acceptMass_event, PMF.toOuterMeasure_map_apply, Function.comp_def]

theorem digest_atom_real (d : Digest) :
    (digestDraw d).toReal = ((2 : ℝ) ^ 256)⁻¹ := by
  rw [digestDraw, PMF.uniformOfFintype_apply]
  simp only [Digest, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat,
    ENNReal.toReal_inv, ENNReal.toReal_pow, ENNReal.toReal_ofNat]

theorem digest_wots_acceptance :
    acceptMass digestDraw (wotsAccept ∘ wotsOfDigest) =
      (Nat.card AcceptedWots : ℝ≥0∞) / 8 ^ 43 := by
  rw [acceptMass_projection, digest_uniform_wots, wots_mass_count]

theorem digest_fors_acceptance :
    acceptMass digestDraw (forsAccept ∘ forsOfDigest) = (2048 : ℝ≥0∞)⁻¹ := by
  rw [acceptMass_projection, digest_uniform_fors, fors_mass_exact]

theorem wots_digest_search_projection (start n : ℕ) :
    (grind digestDraw (wotsAccept ∘ wotsOfDigest) start n).map
      (projectResult wotsOfDigest) = grind wotsDraw wotsAccept start n := by
  rw [grind_projection, digest_uniform_wots]

theorem fors_digest_search_projection (start n : ℕ) :
    (grind digestDraw (forsAccept ∘ forsOfDigest) start n).map
      (projectResult forsOfDigest) = grind forsDraw forsAccept start n := by
  rw [grind_projection, digest_uniform_fors]

theorem wots_digest_exhaustion_real :
    (grind digestDraw (wotsAccept ∘ wotsOfDigest) 0 signingBudget none).toReal =
      (1 - (Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) ^ signingBudget := by
  rw [grind_none_real, digest_wots_acceptance]
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow,
    ENNReal.toReal_ofNat]

theorem fors_digest_exhaustion_real :
    (grind digestDraw (forsAccept ∘ forsOfDigest) 0 signingBudget none).toReal =
      (1 - (1 : ℝ) / 2048) ^ signingBudget := by
  rw [grind_none_real, digest_fors_acceptance]
  simp [one_div]

/-- Full returned digests have mass based on 256 bits, not 129 bits. -/
theorem wots_digest_first_hit (i : ℕ) (d : Digest) :
    (grind digestDraw (wotsAccept ∘ wotsOfDigest) 0 signingBudget
      (some (i, d))).toReal =
      if i < signingBudget ∧ wotsAccept (wotsOfDigest d) = true then
        (1 - (Nat.card AcceptedWots : ℝ) / (8 : ℝ) ^ 43) ^ i / (2 : ℝ) ^ 256 else 0 := by
  rw [grind_some_real, digest_wots_acceptance, digest_atom_real]
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast, ENNReal.toReal_pow,
    ENNReal.toReal_ofNat]
  simp only [Nat.zero_le, zero_add, Nat.sub_zero, true_and, Function.comp_def,
    div_eq_mul_inv]

theorem fors_digest_first_hit (i : ℕ) (d : Digest) :
    (grind digestDraw (forsAccept ∘ forsOfDigest) 0 signingBudget
      (some (i, d))).toReal =
      if i < signingBudget ∧ forsAccept (forsOfDigest d) = true then
        (1 - (1 : ℝ) / 2048) ^ i / (2 : ℝ) ^ 256 else 0 := by
  rw [grind_some_real, digest_fors_acceptance, digest_atom_real]
  simp only [Nat.zero_le, zero_add, Nat.sub_zero, true_and, Function.comp_def,
    ENNReal.toReal_inv, ENNReal.toReal_ofNat, div_eq_mul_inv, one_mul]

end
end C10Probability
