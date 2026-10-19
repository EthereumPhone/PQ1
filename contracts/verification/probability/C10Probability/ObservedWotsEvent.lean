import C10Probability.WotsCutRecurrence

/-! The selected opening event in the original observed game. It uses the
actual forged coordinate and final cache; no probe observer appears in the
event. The auxiliary probe game supplies an exact probability comparison. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def observedWotsCoordinate (out : C10ObservedGame) (layer : ℕ) (chain : Fin 43) : Randomizer :=
  ((out.driver.session.session.value.2.layers[layer]?).getD emptyLayerSignature).sigma chain

def observedWotsSelectedOpening (target : WotsCutTarget) (cfg : C10SessionConfig) :
    Set (C10ObservedGame × Memo WotsQuery Digest) :=
  {out | ¬ WotsReturned target (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures out.2 ∧
    replayProgram out.2 (wotsCutProgram out.1.key.1 target) =
      some (observedWotsCoordinate out.1 (wotsTargetLayer target.1) target.1.2)}

def ObservedWotsOpening (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) : Prop :=
  ∃ target, out ∈ observedWotsSelectedOpening target cfg

theorem c10_probed_game_seed (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (out : C10ProbedGame × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw
      (c10ProbedGameProgram cfg publicSeed adversary qr qs) table).support) :
    out.1.1.key.1 = wotsGameSeed publicSeed := by
  rw [c10ProbedGameProgram, evalProgram_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨key, keySupport, supported⟩ := supported
  rw [evalProgram_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨driver, _, rfl⟩ := supported
  rw [c10KeygenProgram, evalProgram_mapReturn, PMF.mem_support_map_iff] at keySupport
  obtain ⟨root, _, rfl⟩ := keySupport
  rfl

theorem observed_wots_selected_probed (target : WotsCutTarget) (cfg : C10SessionConfig)
    (seed : ByteKey) (qr : ℕ) (out : C10ProbedGame × Memo WotsQuery Digest)
    (seedEqual : out.1.1.key.1 = seed)
    (opening : (out.1.1, out.2) ∈ observedWotsSelectedOpening target cfg) :
    out ∈ wotsProbedOpeningEvent seed target cfg qr := by
  obtain ⟨unreturned, replayed⟩ := opening
  rw [seedEqual] at replayed
  refine ⟨unreturned, observedWotsCoordinate out.1.1 (wotsTargetLayer target.1) target.1.2,
    replayed, ?_⟩
  rcases target with ⟨⟨address | address, chain⟩, cut⟩
  · exact wots_forged_lower_candidate (qr + 361) chain out.1
  · exact wots_forged_upper_candidate (qr + 361) chain out.1

theorem c10_observed_wots_selected_bound (target : WotsCutTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (c10ObservedGame id cfg publicSeed adversary qr qs (fun _ => none)).toOuterMeasure
      (observedWotsSelectedOpening target cfg) ≤
        ((target.2.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs := by
  rw [← c10_probed_game_erases cfg publicSeed adversary qr qs (fun _ => none),
    PMF.toOuterMeasure_map_apply]
  refine le_trans ?_ (wots_probed_opening_bound target cfg publicSeed adversary qr qs)
  apply PMF.toOuterMeasure_mono
  intro out member
  exact observed_wots_selected_probed target cfg (wotsGameSeed publicSeed) qr out
    (c10_probed_game_seed cfg publicSeed adversary qr qs (fun _ => none) out member.2) member.1

theorem c10_initialized_wots_selected_bound (target : WotsCutTarget) (cfg : C10SessionConfig)
    {fuel : ℕ} (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedInitializedIndependent cfg sampler qr qs).toOuterMeasure
      (observedWotsSelectedOpening target cfg) ≤
        ((target.2.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs := by
  rw [c10ObservedInitializedIndependent, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' input, sampler input * (((target.2.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs) := by
      apply ENNReal.tsum_le_tsum
      intro input
      exact mul_le_mul_right (c10_observed_wots_selected_bound target cfg input.1 input.2 qr qs) _
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

end
end C10Probability
