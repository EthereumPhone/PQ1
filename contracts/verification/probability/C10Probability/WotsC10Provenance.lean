import C10Probability.WotsHypertreeProvenance
import C10Probability.WotsC10Release

/-! C10 deferred metadata is authenticated by replay of its actual R search,
forest and both WOTS count searches. The witnesses concern the full final
cache and are stable under any later execution. -/
namespace C10Probability
noncomputable section

def WotsC10MetadataReplay (seed root random message shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (secret : Digest)
    {target : WotsCutTarget} (result : WotsDeferredC10 target) (table : Memo WotsQuery Digest) : Prop :=
  ∃ trial,
    replayProgram table (randomizerUnderProgram id random message seed root m hm) =
      some (some (trial, result.randomizer, result.digest)) ∧
    replayProgram table (forestSignProgram id seed (hypertreeIndex result.digest) result.digest shuffle) =
      some result.forest ∧
    WotsHypertreeCountReplay seed shuffle n hn result.forest.pk secret result.signed table

theorem wots_c10_metadata_replay_extends (seed root random message shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (secret : Digest)
    {target : WotsCutTarget} (result : WotsDeferredC10 target) (before after : Memo WotsQuery Digest)
    (extension : MemoExtends before after)
    (valid : WotsC10MetadataReplay seed root random message shuffle m n hm hn secret result before) :
    WotsC10MetadataReplay seed root random message shuffle m n hm hn secret result after := by
  obtain ⟨trial, randomizer, forest, counts⟩ := valid
  exact ⟨trial, replay_program_extends _ before after _ extension randomizer,
    replay_program_extends _ before after _ extension forest,
    wots_hypertree_count_replay_extends seed shuffle n hn result.forest.pk secret result.signed
      before after extension counts⟩

theorem wots_c10_finish_metadata_replay (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (randomizer : Randomizer) (digest : Digest) (shuffle : ByteKey)
    (n : ℕ) (bound : n ≤ 2 ^ 32) (secret : Digest) (table : Memo WotsQuery Digest)
    (opened : Bool) (cached : table (wotsCutIncoming seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredC10 target)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsC10FinishDeferred seed target previous randomizer digest shuffle n bound) table opened).support)
    (result : WotsDeferredC10 target) (returned : out.value = some result) :
    result.randomizer = randomizer ∧ result.digest = digest ∧
    replayProgram out.cache (forestSignProgram id seed (hypertreeIndex result.digest) result.digest shuffle) =
      some result.forest ∧
    WotsHypertreeCountReplay seed shuffle n bound result.forest.pk secret result.signed out.cache := by
  rw [wotsC10FinishDeferred, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨forest, forestSupport, supported⟩ := supported
  rw [eval_opening_lift, PMF.mem_support_map_iff] at forestSupport
  obtain ⟨built, builtSupport, rfl⟩ := forestSupport
  rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨signed, signSupport, rfl⟩ := supported
  dsimp only at returned ⊢
  cases signedValue : signed.value with
  | none =>
    simp only [wotsDeferredFinish, signedValue, Option.map_none] at returned
    cases returned
  | some layers =>
    have resultEq : (⟨randomizer, digest, built.1, layers⟩ : WotsDeferredC10 target) = result := by
      simpa only [wotsDeferredFinish, signedValue, Option.map_some, Option.some.injEq] using returned
    subst result
    have extension : MemoExtends built.2 signed.cache := by
      intro key value present
      exact eval_opening_preserves digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
        (wotsHypertreeOpening seed target previous shuffle n bound (wotsDigestIndex digest) built.1.pk)
        built.2 opened key value present signed signSupport
    have stillCached := evalProgram_preserves digestDraw _ table
      (wotsCutIncoming seed target previous) secret cached built builtSupport
    exact ⟨rfl, rfl, eval_program_replay_later digestDraw _ table built builtSupport signed.cache extension,
      wots_hypertree_opening_count_replay seed target previous shuffle n bound (wotsDigestIndex digest)
        built.1.pk secret built.2 opened stillCached signed signSupport layers signedValue⟩

theorem wots_c10_sign_metadata_replay (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (random message root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (secret : Digest)
    (table : Memo WotsQuery Digest) (opened : Bool)
    (cached : table (wotsCutIncoming seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest (Option (WotsDeferredC10 target)))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsC10SignDeferred seed target previous random message root shuffle m n hm hn) table opened).support)
    (result : WotsDeferredC10 target) (returned : out.value = some result) :
    WotsC10MetadataReplay seed root random message shuffle m n hm hn secret result out.cache := by
  rw [wotsC10SignDeferred, eval_opening_cast, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨found, foundSupport, supported⟩ := supported
  rw [eval_opening_lift, PMF.mem_support_map_iff] at foundSupport
  obtain ⟨first, firstSupport, rfl⟩ := foundSupport
  have extension : MemoExtends first.2 out.cache := by
    intro key value present
    exact eval_opening_preserves digestDraw (wotsCutCommit seed target) randomizerOfDigest secret
      (wotsC10AfterDeferred seed target previous shuffle n hn first.1) first.2 opened
      key value present out supported
  have counted := eval_program_replay_later digestDraw _ table first firstSupport out.cache extension
  have stillCached := evalProgram_preserves digestDraw _ table
    (wotsCutIncoming seed target previous) secret cached first firstSupport
  cases foundValue : first.1 with
  | none =>
    have equal : out = ⟨none, first.2, opened⟩ := by
      simpa only [foundValue, wotsC10AfterDeferred, evalOpening, PMF.mem_support_pure_iff] using supported
    rw [equal] at returned
    cases returned
  | some value =>
    obtain ⟨trial, randomizer, digest⟩ := value
    rw [foundValue] at supported counted
    obtain ⟨randomizerEq, digestEq, forest, counts⟩ :=
      wots_c10_finish_metadata_replay seed target previous randomizer digest shuffle n hn secret
        first.2 opened stillCached out supported result returned
    exact ⟨trial, by simpa only [randomizerEq, digestEq] using counted, forest, counts⟩

end
end C10Probability
