import C10Probability.WotsLayerProvenance
import C10Probability.WotsHypertreeOpening

/-! Successful two-layer metadata carries actual lower-layer replay and
both count searches in the final cache. The upper count uses the root returned
by the lower layer, without assuming a separately supplied message. -/
namespace C10Probability
noncomputable section

def WotsHypertreeCountReplay (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (current : Randomizer) (secret : Digest) {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (result : WotsDeferredHypertree target index) (table : Memo WotsQuery Digest) : Prop :=
  ∃ middle,
    replayProgram table (layerSignProgram id seed 0 (hypertreeParent index.val)
      (hypertreeLeaf index.val) current shuffle n bound) =
        some (some (wotsDeferredLayerSignature secret result.lower, middle)) ∧
    replayProgram table (wotsAddressCountProgram seed (wotsLowerAddress index) current n bound) =
      some (some (result.lower.wots.count, result.lower.wots.digest)) ∧
    replayProgram table (wotsAddressCountProgram seed (wotsUpperAddress index) middle n bound) =
      some (some (result.upper.wots.count, result.upper.wots.digest))

theorem wots_hypertree_count_replay_extends (seed shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (current : Randomizer) (secret : Digest) {target : WotsCutTarget} {index : Fin (2 ^ 18)}
    (result : WotsDeferredHypertree target index) (before after : Memo WotsQuery Digest)
    (extension : MemoExtends before after)
    (valid : WotsHypertreeCountReplay seed shuffle n bound current secret result before) :
    WotsHypertreeCountReplay seed shuffle n bound current secret result after := by
  obtain ⟨middle, lower, lowerCount, upperCount⟩ := valid
  exact ⟨middle, replay_program_extends _ before after _ extension lower,
    replay_program_extends _ before after _ extension lowerCount,
    replay_program_extends _ before after _ extension upperCount⟩

theorem wots_hypertree_opening_count_replay (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (shuffle : ByteKey) (n : ℕ) (bound : n ≤ 2 ^ 32)
    (index : Fin (2 ^ 18)) (current : Randomizer) (secret : Digest) (table : Memo WotsQuery Digest)
    (opened : Bool) (cached : table (wotsCutIncoming seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredHypertree target index)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsHypertreeOpening seed target previous shuffle n bound index current) table opened).support)
    (result : WotsDeferredHypertree target index) (returned : out.value = some result) :
    WotsHypertreeCountReplay seed shuffle n bound current secret result out.cache := by
  rw [wotsHypertreeOpening, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨lower, lowerSupport, supported⟩ := supported
  have lowerReplay := wots_layer_opening_replay seed target previous (wotsLowerAddress index)
    current shuffle n bound secret table opened cached lower lowerSupport
  cases lowerValue : lower.value with
  | none =>
    rw [lowerValue] at supported
    have equal : out = ⟨none, lower.cache, lower.opened⟩ := by
      simpa only [evalOpening, PMF.mem_support_pure_iff] using supported
    rw [equal] at returned
    cases returned
  | some value =>
    obtain ⟨lowerSig, middle⟩ := value
    have lowerCount := wots_layer_opening_count_replay seed target previous (wotsLowerAddress index)
      current shuffle n bound secret table opened lower lowerSupport lowerSig middle lowerValue
    simp only [lowerValue, wotsDeferredLayerSigned, Option.map_some] at lowerReplay
    rw [lowerValue] at supported
    dsimp only at supported
    rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
    obtain ⟨upper, upperSupport, rfl⟩ := supported
    dsimp only at returned ⊢
    cases upperValue : upper.value with
    | none =>
      simp only [wotsDeferredTwoOutput, upperValue, Option.map_none] at returned
      cases returned
    | some value =>
      obtain ⟨upperSig, root⟩ := value
      have resultEq : (⟨lowerSig, upperSig, root⟩ : WotsDeferredHypertree target index) = result := by
        simpa only [wotsDeferredTwoOutput, upperValue, Option.map_some, Option.some.injEq] using returned
      subst result
      have extension : MemoExtends lower.cache upper.cache := by
        intro key value present
        exact eval_opening_preserves digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
          (wotsLayerOpening seed target previous (wotsUpperAddress index) middle shuffle n bound)
          lower.cache lower.opened key value present upper upperSupport
      exact ⟨middle, replay_program_extends _ lower.cache upper.cache _ extension lowerReplay,
        replay_program_extends _ lower.cache upper.cache _ extension lowerCount,
        wots_layer_opening_count_replay seed target previous (wotsUpperAddress index)
          middle shuffle n bound secret lower.cache lower.opened upper upperSupport upperSig root upperValue⟩

end
end C10Probability
