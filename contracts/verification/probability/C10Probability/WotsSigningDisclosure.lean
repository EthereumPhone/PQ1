import C10Probability.WotsRecordProvenance
import C10Probability.ObservedForestOpening

/-! A newly marked signing disclosure has an actual successful signature and
a valid complete-history record at or before the cut. This excludes exhausted,
failed and incomplete two-layer computations. -/
namespace C10Probability
noncomputable section

theorem wots_c10_opened (cfg : C10SessionConfig) (target : WotsCutTarget) (previous : Randomizer)
    (req : C10SignRequest) (secret : Digest) (seedWidth : cfg.seed.length = 32)
    (rootWidth : cfg.root.length = 32) (messageWidth : req.message.length = 32)
    (shuffleWidth : req.shuffle.length = 32) (table : Memo WotsQuery Digest)
    (cached : table (wotsCutIncoming cfg.seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest (Option C10Signature))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest secret
      (wotsC10Opening cfg.seed target previous req.random req.message cfg.root req.shuffle
        cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound) table false).support)
    (opened : out.opened = true) :
    ∃ signature record, out.value = some signature ∧
      C10SigningRecordValid id out.cache cfg ⟨req, signature⟩ record ∧ WotsRecordExposes target record := by
  have fullReplay := opening_refines_replay digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
    (wotsCutIncoming cfg.seed target previous) secret id _ _
    (wots_c10_opening_refines cfg.seed target previous req.random req.message cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound secret) table false cached out supported
  rw [wotsC10Opening, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨signed, signSupport, releaseSupport⟩ := supported
  have flag := opening_sealed_flag digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest secret
    (wotsCutIncoming cfg.seed target previous) _
    (wots_c10_sign_deferred_sealed cfg.seed target previous req.random req.message cfg.root req.shuffle
      cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound seedWidth rootWidth messageWidth shuffleWidth)
    table false signed signSupport
  rw [flag] at releaseSupport
  obtain ⟨result, returned, exposed, value, cacheEq⟩ :=
    wots_c10_release_disclosure cfg.seed target secret signed.value signed.cache out releaseSupport opened
  have metadata := wots_c10_sign_metadata_replay cfg.seed target previous req.random req.message cfg.root
    req.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound secret table false cached signed
    signSupport result returned
  rw [id_eq, value] at fullReplay
  obtain ⟨record, valid⟩ := replay_c10_signing_record id out.cache cfg
    ⟨req, wotsDeferredC10Signature secret result⟩ fullReplay
  refine ⟨wotsDeferredC10Signature secret result, record, value, valid, ?_⟩
  apply wots_record_metadata_exposure cfg _ out.cache record valid secret result _ exposed
  simpa only [cacheEq] using metadata

def WotsReturned (target : WotsCutTarget) (cfg : C10SessionConfig) (entries : List C10Exposure)
    (table : Memo WotsQuery Digest) : Prop :=
  ∃ entry ∈ entries, ∃ record, C10SigningRecordValid id table cfg entry record ∧
    WotsRecordExposes target record

theorem wots_returned_extends (target : WotsCutTarget) (cfg : C10SessionConfig)
    (entries : List C10Exposure) (before after : Memo WotsQuery Digest)
    (extension : MemoExtends before after) (returned : WotsReturned target cfg entries before) :
    WotsReturned target cfg entries after := by
  obtain ⟨entry, member, record, valid, exposed⟩ := returned
  exact ⟨entry, member, record, c10_signing_record_valid_extends id before after cfg entry record
    extension valid, exposed⟩

theorem wots_returned_history (target : WotsCutTarget) (cfg : C10SessionConfig)
    (entries : List C10Exposure) (records : List C10SigningRecord) (table : Memo WotsQuery Digest)
    (history : C10SigningHistory id table cfg entries records)
    (returned : WotsReturned target cfg entries table) :
    ∃ record ∈ records, WotsRecordExposes target record := by
  obtain ⟨entry, member, first, valid, exposed⟩ := returned
  obtain ⟨record, present, actual⟩ := exposure_history_entry_member id table cfg entries records history entry member
  exact ⟨record, present, (wots_record_exposure_unique cfg entry table first record valid actual target).mp exposed⟩

end
end C10Probability
