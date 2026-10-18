import C10Probability.ForestPrivateOpening
import C10Probability.C10ExposureHistory

/-! Compare ordinary FORS openings with the complete successful-signing list.
Coverage uses the full hypertree coordinate and the selected leaf of each tree.
An unmatched signing coordinate is not a claim about raw-query disclosure. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_fors_sign_private_value (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (out : Randomizer × List Randomizer)
    (recorded : replayProgram table (forsSignProgram encode seed ht tree target) = some out) :
    ∃ value, table (encode (.inr (forsPrivateTail ht tree target))) = some value ∧
      randomizerOfDigest value = out.1 := by
  unfold forsSignProgram at recorded
  cases cached : table (encode (.inr (forsPrivateTail ht tree target))) with
  | none => simp only [replayProgram, cached, Option.bind_none] at recorded; cases recorded
  | some value =>
    rw [replay_program_cached table _ _ value cached] at recorded
    obtain ⟨result, _, equal⟩ := replay_program_map_witness table _ _ _ recorded
    exact ⟨value, rfl, congrArg Prod.fst equal⟩

theorem forest_sign_record_private_values (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (out : ForestOutput) (record : ForestSigningRecord)
    (valid : ForestSigningRecordValid encode table seed ht digest shuffle out record) (i : Fin 12) :
    ∃ value, table (encode (.inr (forsPrivateTail ht i.val (forestIndex digest i.val)))) = some value ∧
      randomizerOfDigest value = (out.secrets[i.val]?).getD 0 := by
  obtain ⟨result, one, secret, _, _⟩ := valid.slots i
  have signed := (replay_forest_one_recorded encode table seed ht i.val
    (forestIndex digest i.val) result one).1
  obtain ⟨value, cached, equal⟩ := replay_fors_sign_private_value encode table seed ht i.val
    (forestIndex digest i.val) (result.secret, result.auth) signed
  refine ⟨value, cached, ?_⟩
  simpa only [valid.secrets, List.getElem?_set_ne (Nat.ne_of_gt i.isLt), secret,
    Option.getD_some] using equal

theorem c10_signing_forest_private_values (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entry : C10Exposure) (prior : C10SigningRecord)
    (valid : C10SigningRecordValid encode table cfg entry prior) (i : Fin 12) :
    ∃ value, table (encode (.inr (forsPrivateTail (hypertreeIndex prior.digest) i.val
      (forestIndex prior.digest i.val)))) = some value ∧
      randomizerOfDigest value = (entry.signature.secrets[i.val]?).getD 0 := by
  obtain ⟨record, signed⟩ := replay_forest_sign_record encode table cfg.seed
    (hypertreeIndex prior.digest) prior.digest entry.request.shuffle prior.forest valid.forest
  simpa only [valid.secrets] using forest_sign_record_private_values encode table cfg.seed
    (hypertreeIndex prior.digest) prior.digest entry.request.shuffle prior.forest record signed i

def ForestIndexCovered (records : List C10SigningRecord) (digest : Digest) (i : Fin 12) : Prop :=
  ∃ prior ∈ records, hypertreeIndex prior.digest = hypertreeIndex digest ∧
    forestIndex prior.digest i.val = forestIndex digest i.val

def ForestHistoryCovered (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (digest : Digest) (secrets : List Randomizer) : Prop :=
  ∀ i : Fin 12, ∃ prior ∈ records, ∃ entry ∈ entries,
    C10SigningRecordValid encode table cfg entry prior ∧
    hypertreeIndex prior.digest = hypertreeIndex digest ∧
    forestIndex prior.digest i.val = forestIndex digest i.val ∧
    (secrets[i.val]?).getD 0 = (entry.signature.secrets[i.val]?).getD 0

def ForestHistoryUnmatched (encode : WotsQuery → K) (table : Memo K Digest)
    (records : List C10SigningRecord) (digest : Digest) (secrets : List Randomizer) : Prop :=
  ∃ i : Fin 12, (∀ prior ∈ records, hypertreeIndex prior.digest = hypertreeIndex digest →
      forestIndex prior.digest i.val ≠ forestIndex digest i.val) ∧
    ∃ value, table (encode (.inr (forsPrivateTail (hypertreeIndex digest) i.val
      (forestIndex digest i.val)))) = some value ∧
      randomizerOfDigest value = (secrets[i.val]?).getD 0

def ForestHistoryCase (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (digest : Digest) (secrets : List Randomizer) : Prop :=
  ForestHistoryCovered encode table cfg entries records digest secrets ∨
    ForestHistoryUnmatched encode table records digest secrets

theorem forest_history_private_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (digest : Digest) (secrets : List Randomizer)
    (privateValues : ∀ i : Fin 12, ∃ value, table (encode (.inr
      (forsPrivateTail (hypertreeIndex digest) i.val (forestIndex digest i.val)))) = some value ∧
      randomizerOfDigest value = (secrets[i.val]?).getD 0) :
    ForestHistoryCase encode table cfg entries records digest secrets := by
  classical
  by_cases covered : ∀ i : Fin 12, ForestIndexCovered records digest i
  · left
    intro i
    obtain ⟨prior, member, address, index⟩ := covered i
    obtain ⟨entry, entryMember, signed⟩ :=
      exposure_history_record_member encode table cfg entries records history prior member
    obtain ⟨priorValue, priorLookup, priorSecret⟩ :=
      c10_signing_forest_private_values encode table cfg entry prior signed i
    obtain ⟨value, lookup, secret⟩ := privateValues i
    rw [address, index] at priorLookup
    have equal : value = priorValue := Option.some.inj (lookup.symm.trans priorLookup)
    exact ⟨prior, member, entry, entryMember, signed, address, index,
      secret.symm.trans ((congrArg randomizerOfDigest equal).trans priorSecret)⟩
  · right
    push Not at covered
    obtain ⟨i, absent⟩ := covered
    refine ⟨i, ?_, privateValues i⟩
    intro prior member address index
    exact absent ⟨prior, member, address, index⟩

theorem forest_opening_history_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer))
    (pk : Randomizer) (priorDigest : Digest) (shuffle : ByteKey) (prior : ForestOutput)
    (opening : ForestOpeningRecord)
    (valid : ForestOpeningRecordValid encode table cfg.seed (hypertreeIndex digest)
      digest secrets auths pk priorDigest shuffle prior opening) :
    ForestHistoryCase encode table cfg entries records digest secrets := by
  exact forest_history_private_comparison encode table cfg entries records history
    digest secrets valid.privateValues

end
end C10Probability
