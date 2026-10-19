import C10Probability.ObservedOpeningBound
import C10Probability.ForestHistoryOpening

/-! The existing complete-history unmatched FORS case implies a selected
unreturned target event. The union retains all 18 address bits, twelve ordinary
trees and eleven leaf bits. This is one branch of the remaining forge bound. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def ObservedForestOpening (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) : Prop :=
  ∃ digest records, C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
    out.1.driver.session.exposures records ∧
    ForestHistoryUnmatched id out.2 records digest out.1.driver.session.session.value.2.secrets

def ordinaryForsOpeningCharge (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  6442450944 * forsOpeningCharge cfg qr qs

theorem exposure_history_entry_member {K : Type*} (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (entry : C10Exposure) (member : entry ∈ entries) :
    ∃ record ∈ records, C10SigningRecordValid encode table cfg entry record := by
  induction history with
  | nil => cases member
  | @cons head record entries records valid _ ih =>
    rcases List.mem_cons.mp member with equal | later
    · subst entry
      exact ⟨record, List.mem_cons_self .., valid⟩
    · obtain ⟨prior, present, valid⟩ := ih later
      exact ⟨prior, List.mem_cons_of_mem record present, valid⟩

theorem forest_selected_coordinates (target : ForsTarget) (digest : Digest)
    (selected : ForestSelected target (hypertreeIndex digest) digest) :
    hypertreeIndex digest = target.1.val ∧ forestIndex digest target.2.1.val = target.2.2.val := by
  obtain ⟨tree, encoded⟩ := selected
  let chosen : ForsTarget := (⟨hypertreeIndex digest, hypertree_index_bound digest⟩,
    tree, ⟨forestIndex digest tree.val, forest_index_bound digest tree.val⟩)
  have equal : chosen = target := fors_target_key_injective encoded
  have address := congrArg (fun value : ForsTarget => value.1.val) equal
  have treeEqual : tree = target.2.1 := congrArg (fun value : ForsTarget => value.2.1) equal
  have leaf := congrArg (fun value : ForsTarget => value.2.2.val) equal
  exact ⟨address, by simpa only [chosen, treeEqual] using leaf⟩

theorem observed_forest_opening_selected (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (opening : ObservedForestOpening cfg out) :
    ∃ target : ForsTarget, out ∈ observedSelectedOpening target cfg := by
  obtain ⟨digest, records, history, i, unmatched, value, cached, nodeEqual⟩ := opening
  let target : ForsTarget := (⟨hypertreeIndex digest, hypertree_index_bound digest⟩,
    i, ⟨forestIndex digest i.val, forest_index_bound digest i.val⟩)
  refine ⟨target, ?_, value, cached, ?_⟩
  · intro returned
    obtain ⟨entry, member, trial, priorDigest, replayed, selected⟩ := returned
    obtain ⟨prior, priorMember, valid⟩ := exposure_history_entry_member id out.2
      (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures records history entry member
    have same := replay_program_unique _ out.2 _ _ replayed valid.randomizer
    have digestEqual : priorDigest = prior.digest := congrArg (fun result => result.2.2) (Option.some.inj same)
    rw [digestEqual] at selected
    have coordinates := forest_selected_coordinates target prior.digest selected
    exact unmatched prior priorMember coordinates.1 coordinates.2
  · change randomizerOfDigest value ∈ forgedForsCandidates out.1
    rw [nodeEqual]
    exact Finset.mem_image.mpr ⟨i, Finset.mem_univ i, rfl⟩

theorem c10_observed_forest_opening_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedForestOpening cfg out} ≤ ordinaryForsOpeningCharge cfg qr qs := by
  calc
    _ ≤ (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
        (⋃ target : ForsTarget, observedSelectedOpening target cfg) := by
      apply MeasureTheory.OuterMeasure.mono
      intro out opening
      obtain ⟨target, member⟩ := observed_forest_opening_selected cfg out opening
      exact Set.mem_iUnion.mpr ⟨target, member⟩
    _ ≤ ∑ target : ForsTarget, (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
        (observedSelectedOpening target cfg) := MeasureTheory.measure_iUnion_fintype_le _ _
    _ ≤ ∑ _ : ForsTarget, forsOpeningCharge cfg qr qs := by
      exact Finset.sum_le_sum (fun target _ => c10_initialized_selected_opening_bound target cfg sampler qr qs)
    _ = _ := by simp [ordinaryForsOpeningCharge, nsmul_eq_mul]

theorem ordinary_fors_opening_charge_ne_top (cfg : C10SessionConfig) (qr qs : ℕ) :
    ordinaryForsOpeningCharge cfg qr qs ≠ ⊤ := by
  exact ENNReal.mul_ne_top (by finiteness) (fors_opening_charge_ne_top cfg qr qs)

theorem c10_observed_forest_opening_bound_real (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    ((c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      {out | ObservedForestOpening cfg out}).toReal ≤
      (6442450944 : ℝ) * min
        (((177526 + qr + qs * 408408 : ℕ) : ℝ) / 2 ^ 128)
        (((177524 + qr + qs * (sessionSignCost cfg + 1) : ℕ) : ℝ) / 2 ^ 128) := by
  have bound := ENNReal.toReal_mono (ordinary_fors_opening_charge_ne_top cfg qr qs)
    (c10_observed_forest_opening_bound cfg sampler qr qs)
  have first : ((177526 + qr + qs * 408408 : ℕ) : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ :=
    ENNReal.div_ne_top (by finiteness) (by simp)
  have second : ((177524 + qr + qs * (sessionSignCost cfg + 1) : ℕ) : ℝ≥0∞) / 2 ^ 128 ≠ ⊤ :=
    ENNReal.div_ne_top (by finiteness) (by simp)
  simpa only [ordinaryForsOpeningCharge, forsOpeningCharge, ENNReal.toReal_mul,
    ENNReal.toReal_ofNat, ENNReal.toReal_min first second, ENNReal.toReal_div,
    ENNReal.toReal_natCast, ENNReal.toReal_pow] using bound

end
end C10Probability
