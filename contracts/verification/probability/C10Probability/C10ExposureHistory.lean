import C10Probability.C10RecordStability

/-! The complete chronological successful-signing ledger has one paired
record per exposure, including duplicates. Each record retains both layers;
no successful entry is filtered away or replaced by a selected subset. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def C10SigningHistory (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord) : Prop :=
  List.Forall₂ (C10SigningRecordValid encode table cfg) entries records

theorem exposure_history_exists (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure)
    (supported : ∀ entry ∈ entries, ExposureSupported encode cfg table entry) :
    ∃ records, C10SigningHistory encode table cfg entries records := by
  induction entries with
  | nil => exact ⟨[], .nil⟩
  | cons entry entries ih =>
    obtain ⟨record, valid⟩ := exposure_supported_signing_record encode table cfg entry
      (supported entry (List.mem_cons_self ..))
    obtain ⟨records, history⟩ := ih (fun e member => supported e (List.mem_cons_of_mem entry member))
    exact ⟨record :: records, .cons valid history⟩

theorem exposure_history_length (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) :
    entries.length = records.length := by
  induction history with
  | nil => rfl
  | cons _ _ ih => exact congrArg Nat.succ ih

theorem exposure_history_record_member (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (candidate : C10SigningRecord) (member : candidate ∈ records) :
    ∃ entry ∈ entries, C10SigningRecordValid encode table cfg entry candidate := by
  induction history with
  | nil => cases member
  | @cons entry record entries records valid _ ih =>
    rcases List.mem_cons.mp member with same | later
    · subst candidate
      exact ⟨entry, List.mem_cons_self .., valid⟩
    · obtain ⟨e, present, he⟩ := ih later
      exact ⟨e, List.mem_cons_of_mem entry present, he⟩

theorem exposure_history_lower_word_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (first second : C10SigningRecord) (one : first ∈ records) (two : second ∈ records)
    (tree : hypertreeParent (hypertreeIndex first.digest) = hypertreeParent (hypertreeIndex second.digest))
    (leaf : hypertreeLeaf (hypertreeIndex first.digest) = hypertreeLeaf (hypertreeIndex second.digest)) :
    wotsOfDigest first.lowerDigest = wotsOfDigest second.lowerDigest := by
  obtain ⟨firstEntry, _, firstValid⟩ := exposure_history_record_member encode table cfg entries records history first one
  obtain ⟨secondEntry, _, secondValid⟩ := exposure_history_record_member encode table cfg entries records history second two
  exact congrArg wotsOfDigest (c10_record_lower_wots_eq encode table cfg firstEntry secondEntry
    first second firstValid secondValid tree leaf).2.1

theorem exposure_history_upper_word_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records)
    (first second : C10SigningRecord) (one : first ∈ records) (two : second ∈ records)
    (leaf : hypertreeLeaf (hypertreeParent (hypertreeIndex first.digest)) =
      hypertreeLeaf (hypertreeParent (hypertreeIndex second.digest))) :
    wotsOfDigest first.upperDigest = wotsOfDigest second.upperDigest := by
  obtain ⟨firstEntry, _, firstValid⟩ := exposure_history_record_member encode table cfg entries records history first one
  obtain ⟨secondEntry, _, secondValid⟩ := exposure_history_record_member encode table cfg entries records history second two
  exact congrArg wotsOfDigest (c10_record_upper_wots_eq encode table cfg firstEntry secondEntry
    first second firstValid secondValid leaf).2.1

theorem observed_output_signing_history (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) (qr qs : ℕ) (out : C10ObservedGame × Memo K Digest)
    (witness : ObservedOutputWitness encode cfg publicSeed qr qs out) :
    ∃ records, C10SigningHistory encode out.2 (sessionConfigAt cfg out.1.key)
      out.1.driver.session.exposures records ∧ records.length ≤ qs := by
  obtain ⟨records, history⟩ := exposure_history_exists encode out.2
    (sessionConfigAt cfg out.1.key) out.1.driver.session.exposures witness.exposures
  have length := exposure_history_length encode out.2 (sessionConfigAt cfg out.1.key)
    out.1.driver.session.exposures records history
  have accounting := witness.sign_accounting
  exact ⟨records, history, by omega⟩

end
end C10Probability
