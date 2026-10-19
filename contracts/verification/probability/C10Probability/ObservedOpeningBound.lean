import C10Probability.SelectedOpeningEvent
import C10Probability.ObservedOpeningDisclosure
import C10Probability.ObservedInitialized

/-! A selected unreturned ordinary FORS node in the actual initialized game.
The twelve final slots include defaults and duplicate values. The minimum keeps
both the derived variable-candidate charge and the conservative full-work bound. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def forgedForsCandidates (out : C10ObservedGame) : Finset Randomizer :=
  Finset.univ.image (fun i : Fin 12 =>
    (out.driver.session.session.value.2.secrets[i.val]?).getD 0)

def observedSelectedOpening (target : ForsTarget) (cfg : C10SessionConfig) :
    Set (C10ObservedGame × Memo WotsQuery Digest) :=
  selectedOpeningEvent (forsTargetKey target) randomizerOfDigest forgedForsCandidates
    (fun out table => ForsReturned target (sessionConfigAt cfg out.key) out.driver.session.exposures table)

def forsOpeningCharge (cfg : C10SessionConfig) (qr qs : ℕ) : ℝ≥0∞ :=
  min (((177526 + qr + qs * 408408 : ℕ) : ℝ≥0∞) / 2 ^ 128)
    (((177524 + qr + qs * (sessionSignCost cfg + 1) : ℕ) : ℝ≥0∞) / 2 ^ 128)

theorem forged_fors_candidates_card (out : C10ObservedGame) : (forgedForsCandidates out).card ≤ 12 := by
  exact (Finset.card_image_le).trans (by simp)

theorem c10_observed_selected_opening_bound (target : ForsTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (c10ObservedGame id cfg publicSeed adversary qr qs (fun _ => none)).toOuterMeasure
      (observedSelectedOpening target cfg) ≤ forsOpeningCharge cfg qr qs := by
  let instrumented := c10ObservedGameOpening target cfg publicSeed adversary qr qs
  have comparison := selected_opening_comparison digestDraw nodeCommitEncode randomizerOfDigest
    (forsTargetKey target) forgedForsCandidates
    (fun out table => ForsReturned target (sessionConfigAt cfg out.key) out.driver.session.exposures table)
    (c10ObservedGameProgram id cfg publicSeed adversary qr qs) instrumented
    (fun secret => c10_observed_game_opening_refines target secret cfg publicSeed adversary qr qs)
    (c10_observed_game_opening_avoids target cfg publicSeed adversary qr qs)
    (fun _ _ => fors_target_not_public target _)
    (fun secret table out supported opened =>
      c10_observed_game_opened target secret cfg publicSeed adversary qr qs table out supported opened)
  rw [c10_observed_game_program_eval] at comparison
  apply le_min
  · refine comparison.trans ?_
    have bound := node_opening_candidate_bound (PMF.pure instrumented)
      (177151 + (qr + qs * 408408) + 361) 12 ?_ forgedForsCandidates forged_fors_candidates_card
    · simpa only [show 177151 + (qr + qs * 408408) + 361 + 2 + 12 =
        177526 + qr + qs * 408408 by omega] using bound
    · intro program supported
      have equal : program = instrumented := by simpa only [PMF.mem_support_pure_iff] using supported
      subst program
      exact c10_observed_game_opening_budget target cfg publicSeed adversary qr qs
  · refine comparison.trans ?_
    have bound := opening_candidate_bound digestDraw digestDraw nodeCommitEncode nodeQueryDecode
      randomizerOfDigest randomizer_uniform node_commit_decodes node_commit_labels_injective
      (PMF.pure instrumented) ((361 + (qr + qs * (sessionSignCost cfg + 1))) + 177151) 12
      (fun _ _ => publicBudget_total _) forgedForsCandidates forged_fors_candidates_card
    simpa only [Randomizer, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat,
      show (361 + (qr + qs * (sessionSignCost cfg + 1)) + 177151) + 12 =
        177524 + qr + qs * (sessionSignCost cfg + 1) by omega] using bound

theorem c10_initialized_selected_opening_bound (target : ForsTarget) (cfg : C10SessionConfig)
    {fuel : ℕ} (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      (observedSelectedOpening target cfg) ≤ forsOpeningCharge cfg qr qs := by
  rw [c10ObservedInitializedIndependent, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' input, sampler input * forsOpeningCharge cfg qr qs := by
      apply ENNReal.tsum_le_tsum
      intro input
      exact mul_le_mul_right (c10_observed_selected_opening_bound target cfg input.1 input.2 qr qs) _
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

theorem fors_opening_charge_ne_top (cfg : C10SessionConfig) (qr qs : ℕ) :
    forsOpeningCharge cfg qr qs ≠ ⊤ := by
  unfold forsOpeningCharge
  exact ne_top_of_le_ne_top (ENNReal.div_ne_top (by finiteness) (by simp)) (min_le_left _ _)

end
end C10Probability
