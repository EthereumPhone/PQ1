import C10Probability.GrowthFactorization
import C10Probability.ForsWitnessPositions
import C10Probability.ForsSamplePrefix

/-! Ordinary-coordinate coverage in a pool. Different coordinates may use
different earlier samples, but the target position itself is excluded. All
witnesses retain the target's complete hypertree address. -/
namespace C10Probability
noncomputable section

def ForsPoolCoverage {n : ℕ} (samples : Fin n → Digest) : Prop :=
  ∃ target, ∀ coordinate : Fin 12, ∃ position,
    position ≠ target ∧ hypertreeIndex (samples position) = hypertreeIndex (samples target) ∧
      forestIndex (samples position) coordinate.val = forestIndex (samples target) coordinate.val

def ForsCoverageByGroups {n : ℕ} (samples : Fin n → Digest) (j : ℕ) : Prop :=
  ∃ target, ∃ word : GrowthWord 12 j, ∃ positions : Fin j ↪ ForsOtherPosition target,
    ∀ group, samples (positions group).val ∈
      forsGroupEvent (growthAssignment word) group (samples target)

theorem fors_pool_coverage_canonical {n : ℕ} (samples : Fin n → Digest) :
    ForsPoolCoverage samples ↔ ∃ j, 0 < j ∧ j ≤ 12 ∧ ForsCoverageByGroups samples j := by
  classical
  constructor
  · rintro ⟨target, covered⟩
    choose position different address index using covered
    let chosen : Fin 12 → ForsOtherPosition target := fun i => ⟨position i, different i⟩
    obtain ⟨j, positive, bounded, word, positions, agrees⟩ :=
      growth_nonempty_factorization (by decide : 0 < 12) chosen
    refine ⟨j, positive, bounded, target, word, positions, ?_⟩
    intro group
    rw [fors_group_event_coordinates]
    constructor
    · obtain ⟨i, hi⟩ := growth_assignment_surjective word group
      have same : position i = (positions group).val := by
        simpa only [chosen, hi] using congrArg Subtype.val (agrees i)
      rw [← same]
      exact address i
    · intro i hi
      have same : position i = (positions group).val := by
        simpa only [chosen, hi] using congrArg Subtype.val (agrees i)
      rw [← same]
      exact index i
  · rintro ⟨j, _, _, target, word, positions, groups⟩
    refine ⟨target, ?_⟩
    intro i
    let group := growthAssignment word i
    have hm := (fors_group_event_coordinates (growthAssignment word) group
      (samples target) (samples (positions group).val)).mp (groups group)
    exact ⟨(positions group).val, (positions group).property, hm.1, hm.2 i rfl⟩

theorem fors_pool_coverage_selection {m n : ℕ} (samples : Fin n → Digest)
    (select : Fin m → Fin n) (distinct : Function.Injective select)
    (covered : ForsPoolCoverage (fun i => samples (select i))) : ForsPoolCoverage samples := by
  obtain ⟨target, witnesses⟩ := covered
  refine ⟨select target, ?_⟩
  intro i
  obtain ⟨position, different, address, index⟩ := witnesses i
  exact ⟨select position, fun same => different (distinct same), address, index⟩

def ForsListCoverage (samples : List Digest) : Prop :=
  ForsPoolCoverage (fun i : Fin samples.length => samples[i])

theorem fors_list_coverage_extension : SampleExtensionClosed ForsListCoverage := by
  intro before after covered
  let select : Fin before.length → Fin (before ++ after).length :=
    fun i => ⟨i.val, by simp only [List.length_append]; omega⟩
  have distinct : Function.Injective select := by
    intro a b same
    exact Fin.ext (congrArg (fun i : Fin (before ++ after).length => i.val) same)
  apply fors_pool_coverage_selection (fun i => (before ++ after)[i]) select distinct
  have same : (fun i : Fin before.length => (before ++ after)[select i]) =
      (fun i : Fin before.length => before[i]) := by
    funext i
    simp [select, List.getElem_append_left]
  rw [same]
  exact covered

theorem fors_list_coverage_ofFn {n : ℕ} (samples : Fin n → Digest) :
    ForsListCoverage (List.ofFn samples) ↔ ForsPoolCoverage samples := by
  simp [ForsListCoverage, ForsPoolCoverage, Fin.exists_iff]

end
end C10Probability
