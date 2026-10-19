import C10Probability.ObservedWotsBound
import C10Probability.TopExposureOpening
import C10Probability.LowerExposureOpening

/-! Both existing earlier-than-all-exposures branches imply the bounded
original-game event. Complete successful histories, including duplicates,
exclude every legitimate release at or before the selected cut. -/
namespace C10Probability
noncomputable section

theorem wots_history_unreturned (target : WotsCutTarget) (cfg : C10SessionConfig)
    (entries : List C10Exposure) (records : List C10SigningRecord) (table : Memo WotsQuery Digest)
    (history : C10SigningHistory id table cfg entries records)
    (earlier : ∀ record ∈ records, ¬ WotsRecordExposes target record) :
    ¬ WotsReturned target cfg entries table := by
  intro returned
  obtain ⟨record, member, exposed⟩ := wots_returned_history target cfg entries records table history returned
  exact earlier record member exposed

theorem observed_top_earlier_opening (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (records : List C10SigningRecord)
    (history : C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records) (opening : TopChainRecord) (i : Fin 43)
    (endpoint : (opening.word i).val < 7)
    (replayed : replayProgram out.2 (wotsSeedChainProgram id out.1.key.1 1 0 opening.kp i.val
      (opening.word i).val) = some (observedWotsCoordinate out.1 1 i))
    (earlier : ∀ prior ∈ records,
      hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = opening.kp →
        (opening.word i).val < (wotsOfDigest prior.upperDigest i).val) :
    ObservedWotsOpening cfg out := by
  let target : WotsCutTarget := ((wotsUpperAddress (wotsDigestIndex opening.digest), i),
    ⟨(opening.word i).val, endpoint⟩)
  refine ⟨target, wots_history_unreturned target _ _ records out.2 history ?_, replayed⟩
  intro prior member exposed
  rcases exposed with lower | upper
  · have layer := congrArg (fun address : WotsLogicalAddress => wotsTargetLayer (address, i)) lower.1
    cases layer
  · have address := congrArg (fun address : WotsLogicalAddress => wotsTargetKp (address, i)) upper.1
    have strict := earlier prior member address
    have nonstrict := upper.2
    exact Nat.not_lt_of_ge nonstrict strict

theorem observed_lower_earlier_opening (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (records : List C10SigningRecord)
    (history : C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records) (opening : TopChainRecord) (lower : LowerChainRecord) (i : Fin 43)
    (endpoint : (lower.word i).val < 7)
    (replayed : replayProgram out.2 (wotsSeedChainProgram id out.1.key.1 0 opening.lowerTree
      opening.lowerKp i.val (lower.word i).val) = some (observedWotsCoordinate out.1 0 i))
    (earlier : ∀ prior ∈ records,
      hypertreeParent (hypertreeIndex prior.digest) = opening.lowerTree ∧
      hypertreeLeaf (hypertreeIndex prior.digest) = opening.lowerKp →
        (lower.word i).val < (wotsOfDigest prior.lowerDigest i).val) :
    ObservedWotsOpening cfg out := by
  let target : WotsCutTarget := ((wotsLowerAddress (wotsDigestIndex opening.digest), i),
    ⟨(lower.word i).val, endpoint⟩)
  refine ⟨target, wots_history_unreturned target _ _ records out.2 history ?_, replayed⟩
  intro prior member exposed
  rcases exposed with lo | upper
  · have tree := congrArg (fun address : WotsLogicalAddress => wotsTargetTree (address, i)) lo.1
    have kp := congrArg (fun address : WotsLogicalAddress => wotsTargetKp (address, i)) lo.1
    have strict := earlier prior member ⟨tree, kp⟩
    exact Nat.not_lt_of_ge lo.2 strict
  · have layer := congrArg (fun address : WotsLogicalAddress => wotsTargetLayer (address, i)) upper.1
    cases layer

theorem observed_top_exposure_opening (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (records : List C10SigningRecord)
    (history : C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records) (opening : TopChainRecord)
    (cases : TopExposureCase id out.2 out.1.key.1 out.1.driver.session.session.value.2 records opening) :
    (∃ prior ∈ records, hypertreeLeaf (hypertreeParent (hypertreeIndex prior.digest)) = opening.kp ∧
      opening.word = wotsOfDigest prior.upperDigest ∧
      ((out.1.driver.session.session.value.2.layers[1]?).getD emptyLayerSignature).sigma = prior.upper.sigma) ∨
      ObservedWotsOpening cfg out := by
  rcases cases with same | earlier
  · exact Or.inl same
  · obtain ⟨i, _, endpoint, replayed, allPrior⟩ := earlier
    exact Or.inr (observed_top_earlier_opening cfg out records history opening i endpoint replayed
      (fun prior member address => (allPrior prior member address).1))

theorem observed_lower_exposure_opening (cfg : C10SessionConfig)
    (out : C10ObservedGame × Memo WotsQuery Digest) (records : List C10SigningRecord)
    (history : C10SigningHistory id out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records) (opening : TopChainRecord) (lower : LowerChainRecord)
    (cases : LowerExposureCase id out.2 out.1.key.1 out.1.driver.session.session.value.2 records opening lower) :
    (∃ prior ∈ records, hypertreeParent (hypertreeIndex prior.digest) = opening.lowerTree ∧
      hypertreeLeaf (hypertreeIndex prior.digest) = opening.lowerKp ∧
      lower.word = wotsOfDigest prior.lowerDigest ∧
      ((out.1.driver.session.session.value.2.layers[0]?).getD emptyLayerSignature).sigma = prior.lower.sigma) ∨
      ObservedWotsOpening cfg out := by
  rcases cases with same | earlier
  · exact Or.inl same
  · obtain ⟨i, _, endpoint, replayed, allPrior⟩ := earlier
    exact Or.inr (observed_lower_earlier_opening cfg out records history opening lower i endpoint replayed
      (fun prior member address => (allPrior prior member address).1))

end
end C10Probability
