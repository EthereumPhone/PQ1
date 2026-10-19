import C10Probability.WotsC10Provenance
import C10Probability.C10ExposureHistory

/-! Deferred digests agree with every valid actual signing record for the
same request. Thus marking a legitimate release is a statement about the
complete existing exposure history, not a separate symbolic history. -/
namespace C10Probability
noncomputable section

def WotsRecordExposes (target : WotsCutTarget) (record : C10SigningRecord) : Prop :=
  (wotsLowerAddress (wotsDigestIndex record.digest) = target.1.1 ∧
    (wotsOfDigest record.lowerDigest target.1.2).val ≤ target.2.val) ∨
  (wotsUpperAddress (wotsDigestIndex record.digest) = target.1.1 ∧
    (wotsOfDigest record.upperDigest target.1.2).val ≤ target.2.val)

theorem wots_c10_metadata_record_equal (cfg : C10SessionConfig) (entry : C10Exposure)
    (table : Memo WotsQuery Digest) (record : C10SigningRecord)
    (valid : C10SigningRecordValid id table cfg entry record) (secret : Digest)
    {target : WotsCutTarget} (result : WotsDeferredC10 target)
    (metadata : WotsC10MetadataReplay cfg.seed cfg.root entry.request.random entry.request.message
      entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound secret result table) :
    record.digest = result.digest ∧ record.lowerDigest = result.signed.lower.wots.digest ∧
      record.upperDigest = result.signed.upper.wots.digest := by
  obtain ⟨trial, randomizer, forest, middle, lower, lowerCount, upperCount⟩ := metadata
  have randomizerEq := Option.some.inj (replay_program_unique _ table _ _ valid.randomizer randomizer)
  have digestEq : record.digest = result.digest := congrArg (fun value => value.2.2) randomizerEq
  have forestRecorded := valid.forest
  rw [digestEq] at forestRecorded
  have forestEq := replay_program_unique _ table _ _ forestRecorded forest
  have lowerRecorded := valid.lower
  rw [digestEq, forestEq] at lowerRecorded
  have lowerEq := Option.some.inj (replay_program_unique _ table _ _ lowerRecorded lower)
  have middleEq : record.middle = middle := congrArg Prod.snd lowerEq
  have lowerCountRecorded := valid.lower_count
  rw [digestEq, forestEq] at lowerCountRecorded
  have lowerCountEq := Option.some.inj (replay_program_unique _ table _ _ lowerCountRecorded lowerCount)
  have upperCountRecorded := valid.upper_count
  rw [digestEq, middleEq] at upperCountRecorded
  have upperCountEq := Option.some.inj (replay_program_unique _ table _ _ upperCountRecorded upperCount)
  exact ⟨digestEq, congrArg Prod.snd lowerCountEq, congrArg Prod.snd upperCountEq⟩

theorem wots_record_metadata_exposure (cfg : C10SessionConfig) (entry : C10Exposure)
    (table : Memo WotsQuery Digest) (record : C10SigningRecord)
    (valid : C10SigningRecordValid id table cfg entry record) (secret : Digest)
    {target : WotsCutTarget} (result : WotsDeferredC10 target)
    (metadata : WotsC10MetadataReplay cfg.seed cfg.root entry.request.random entry.request.message
      entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound secret result table)
    (exposed : WotsHypertreeExposes result.signed) : WotsRecordExposes target record := by
  obtain ⟨digestEq, lowerEq, upperEq⟩ :=
    wots_c10_metadata_record_equal cfg entry table record valid secret result metadata
  simpa only [WotsRecordExposes, digestEq, lowerEq, upperEq, WotsHypertreeExposes,
    WotsResultExposes] using exposed

theorem c10_signing_record_valid_extends {K : Type*} (encode : WotsQuery → K)
    (before after : Memo K Digest) (cfg : C10SessionConfig) (entry : C10Exposure)
    (record : C10SigningRecord) (extension : MemoExtends before after)
    (valid : C10SigningRecordValid encode before cfg entry record) :
    C10SigningRecordValid encode after cfg entry record := by
  exact ⟨replay_program_extends _ before after _ extension valid.signing,
    replay_program_extends _ before after _ extension valid.randomizer,
    replay_program_extends _ before after _ extension valid.forest,
    valid.secrets, valid.auths, valid.layers,
    replay_program_extends _ before after _ extension valid.lower,
    replay_program_extends _ before after _ extension valid.upper,
    replay_program_extends _ before after _ extension valid.lower_count,
    replay_program_extends _ before after _ extension valid.upper_count,
    valid.lower_accepted, valid.upper_accepted,
    fun i => replay_program_extends _ before after _ extension (valid.lower_prefixes i),
    fun i => replay_program_extends _ before after _ extension (valid.upper_prefixes i)⟩

theorem wots_record_exposure_unique (cfg : C10SessionConfig) (entry : C10Exposure)
    (table : Memo WotsQuery Digest) (first second : C10SigningRecord)
    (one : C10SigningRecordValid id table cfg entry first)
    (two : C10SigningRecordValid id table cfg entry second) (target : WotsCutTarget) :
    WotsRecordExposes target first ↔ WotsRecordExposes target second := by
  have pairEq := Option.some.inj (replay_program_unique _ table _ _ one.randomizer two.randomizer)
  have digestEq : first.digest = second.digest := congrArg (fun value => value.2.2) pairEq
  have lowerEq := (c10_record_lower_wots_eq id table cfg entry entry first second one two
    (congrArg (fun digest => hypertreeParent (hypertreeIndex digest)) digestEq)
    (congrArg (fun digest => hypertreeLeaf (hypertreeIndex digest)) digestEq)).2.1
  have upperEq := (c10_record_upper_wots_eq id table cfg entry entry first second one two
    (congrArg (fun digest => hypertreeLeaf (hypertreeParent (hypertreeIndex digest))) digestEq)).2.1
  simp only [WotsRecordExposes, digestEq, lowerEq, upperEq]

end
end C10Probability
