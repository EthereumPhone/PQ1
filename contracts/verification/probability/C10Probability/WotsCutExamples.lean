import C10Probability.PresampleProbeExamples

/-! Concrete boundary witnesses keep all18address bits, both layers,
all43coordinates, incoming/outgoing positions and the public endpoint. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def lastLowerWotsTarget : WotsTarget := (.inl (511, 511), 42)
def lastUpperWotsTarget : WotsTarget := (.inr 511, 42)

theorem wots_last_lower_coordinates :
    wotsTargetLayer lastLowerWotsTarget = 0 ∧ wotsTargetTree lastLowerWotsTarget = 511 ∧
      wotsTargetKp lastLowerWotsTarget = 511 ∧ lastLowerWotsTarget.2.val = 42 := by decide +kernel

theorem wots_last_upper_coordinates :
    wotsTargetLayer lastUpperWotsTarget = 1 ∧ wotsTargetTree lastUpperWotsTarget = 0 ∧
      wotsTargetKp lastUpperWotsTarget = 511 ∧ lastUpperWotsTarget.2.val = 42 := by decide +kernel

theorem wots_high_address_bit_example :
    wotsTargetKey (wotsLowerAddress (0 : Fin (2 ^ 18)), 0) ≠
      wotsTargetKey (wotsLowerAddress (131072 : Fin (2 ^ 18)), 0) ∧
    wotsTargetKey (wotsUpperAddress (0 : Fin (2 ^ 18)), 0) ≠
      wotsTargetKey (wotsUpperAddress (131072 : Fin (2 ^ 18)), 0) := by decide +kernel

theorem wots_layer_separation_example :
    wotsTargetKey (.inl (0, 511), 42) ≠ wotsTargetKey lastUpperWotsTarget := by decide +kernel

theorem wots_chain_last_separation_example :
    wotsTargetKey (.inr 511, 41) ≠ wotsTargetKey lastUpperWotsTarget := by decide +kernel

theorem wots_first_cut_private_example (seed : ByteKey) (previous : Randomizer) :
    wotsCutIncoming seed (lastLowerWotsTarget, 0) previous =
      Sum.inr (wotsPrivateTail 0 511 511 42) := by rfl

theorem wots_last_cut_incoming_example (seed : ByteKey) (previous : Randomizer) :
    wotsCutIncoming seed (lastUpperWotsTarget, 6) previous =
      Sum.inl (wotsChainInput seed 1 0 511 42 5 previous) := by rfl

theorem wots_last_cut_outgoing_example (seed : ByteKey) (node : Randomizer) :
    wotsCutCommit seed (lastUpperWotsTarget, 6) node () =
      Sum.inl (wotsChainInput seed 1 0 511 42 6 node) := by rfl

theorem wots_last_cut_previous_example :
    wotsPreviousCut (lastUpperWotsTarget, 6) = (lastUpperWotsTarget, 5) := by rfl

theorem wots_zero_prefix_no_query (seed : ByteKey) (target : WotsTarget) (table : Memo WotsQuery Digest) :
    evalProgram digestDraw (wotsBeforeCutProgram seed target 0) table = PMF.pure (0, table) := by rfl

theorem wots_first_prefix_private_example (seed : ByteKey) (target : WotsTarget) :
    wotsBeforeCutProgram seed target 1 =
      QueryProgram.query (wotsTargetKey target) (fun value => QueryProgram.done (n := 0) (randomizerOfDigest value)) := by rfl

theorem wots_hidden_full_digest_projection (target : WotsCutTarget) :
    wotsDeferredValue (2 ^ 128 : Digest) (hiddenWotsNode target target.1 target.2.val ⟨rfl, rfl⟩) = 1 ∧
    wotsDeferredValue (1 : Digest) (hiddenWotsNode target target.1 target.2.val ⟨rfl, rfl⟩) = 0 := by
  constructor <;> change randomizerOfDigest _ = _ <;> decide +kernel

theorem wots_endpoint_never_hidden (target : WotsCutTarget) (source : WotsTarget)
    (node : WotsDeferredNode target source 7) : node.val ≠ none := by
  intro hidden
  have := (node.property hidden).2
  have := target.2.isLt
  omega

theorem wots_one_request_charge :
    wotsCutCharge 0 1 = (519943 : ℝ≥0∞) / 2 ^ 128 := by norm_num [wotsCutCharge]

theorem wots_no_request_charge (qr : ℕ) :
    wotsCutCharge qr 0 = ((155867 + 2 * qr : ℕ) : ℝ≥0∞) / 2 ^ 128 := by simp [wotsCutCharge]

theorem wots_cap_charge_example :
    ordinaryWotsOpeningCharge (2 ^ 32) 65536 < (1 : ℝ≥0∞) / 2 ^ 64 := by
  apply (ENNReal.toReal_lt_toReal (ordinary_wots_opening_charge_ne_top _ _)
    (ENNReal.div_ne_top (by finiteness) (by simp))).mp
  norm_num [ordinaryWotsOpeningCharge, wotsCutCharge, ENNReal.toReal_mul, ENNReal.toReal_div,
    ENNReal.toReal_pow]

end
end C10Probability
