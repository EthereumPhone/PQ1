import C10Probability.ForsAccepted

/-! Joint accepted-digest coordinates. Opening sets and the target address
are fixed before the draw; their product law is derived, not assumed. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def forsCoordinates (d : Digest) : HypertreeField × ForestWord :=
  ((forsDigestEquiv d).1.1.2, (forsDigestEquiv d).2)

theorem fors_coordinates_address (d : Digest) :
    (forsCoordinates d).1.val = hypertreeIndex d := by
  exact fors_fields_hypertree d

theorem fors_coordinates_index (d : Digest) (i : Fin 12) :
    ((forsCoordinates d).2 i).val = forestIndex d i.val := by
  exact fors_fields_ordinary d i

theorem accepted_fors_coordinates_uniform :
    acceptedForsDraw.map forsCoordinates =
      PMF.uniformOfFintype (HypertreeField × ForestWord) := by
  have erase : (PMF.uniformOfFintype AcceptedForsFields).map
      (fun fields => (fields.1.2, fields.2)) =
      PMF.uniformOfFintype (HypertreeField × ForestWord) := by
    have h := congrArg (PMF.map (Prod.snd :
      Fin (2 ^ 95) × (HypertreeField × ForestWord) → HypertreeField × ForestWord))
      (uniform_map_equiv (Equiv.prodAssoc (Fin (2 ^ 95)) HypertreeField ForestWord))
    rw [uniform_map_snd] at h
    simpa only [PMF.map_comp, Function.comp_def, Equiv.prodAssoc_apply] using h
  have h := congrArg (PMF.map (fun fields : AcceptedForsFields => (fields.1.2, fields.2)))
    (uniform_map_equiv acceptedForsEquiv)
  rw [erase] at h
  simpa only [acceptedForsDraw, PMF.map_comp, Function.comp_def,
    acceptedForsEquiv, forsCoordinates] using h

def forsCoordinateSet (address : HypertreeField) (opened : Fin 12 → Finset ForsField) :
    Finset (HypertreeField × ForestWord) :=
  {address} ×ˢ Fintype.piFinset opened

theorem fors_coordinate_set_member (address : HypertreeField)
    (opened : Fin 12 → Finset ForsField) (coordinates : HypertreeField × ForestWord) :
    coordinates ∈ forsCoordinateSet address opened ↔
      coordinates.1 = address ∧ ∀ i, coordinates.2 i ∈ opened i := by
  simp only [forsCoordinateSet, Finset.mem_product, Finset.mem_singleton,
    Fintype.mem_piFinset]

theorem accepted_fors_coordinate_mass (address : HypertreeField)
    (opened : Fin 12 → Finset ForsField) :
    acceptedForsDraw.toOuterMeasure {d | forsCoordinates d ∈ forsCoordinateSet address opened} =
      (∏ i, ((opened i).card : ℝ≥0∞)) / ((2 : ℝ≥0∞) ^ 18 * 2048 ^ 12) := by
  have h := congrArg (fun p : PMF (HypertreeField × ForestWord) =>
    p.toOuterMeasure (forsCoordinateSet address opened : Set (HypertreeField × ForestWord)))
    accepted_fors_coordinates_uniform
  dsimp only at h
  rw [PMF.toOuterMeasure_map_apply, PMF.toOuterMeasure_uniformOfFintype_apply] at h
  have count : Fintype.card (forsCoordinateSet address opened : Set (HypertreeField × ForestWord)) =
      (forsCoordinateSet address opened).card := Fintype.card_coe _
  rw [count] at h
  simpa only [Set.preimage, Finset.mem_coe, forsCoordinateSet,
    Finset.card_product, Finset.card_singleton, Fintype.card_piFinset, one_mul,
    HypertreeField, ForestWord, ForsField, Fintype.card_prod, Fintype.card_fun,
    Fintype.card_fin, Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat, Nat.cast_prod] using h

end
end C10Probability
