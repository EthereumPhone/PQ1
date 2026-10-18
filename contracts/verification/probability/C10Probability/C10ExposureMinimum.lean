import C10Probability.C10ExposureHistory
import C10Probability.ExposureMinimum

/-! Filter the complete actual signing history by logical address, retaining
every matching occurrence, then compute its exact positional minimum. The
uniform-word premise is discharged from C10's actual signing records. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def lowerExposureWords (records : List C10SigningRecord) (tree kp : ℕ) : List WotsWord :=
  (records.filter (fun record => decide
    (hypertreeParent (hypertreeIndex record.digest) = tree ∧
      hypertreeLeaf (hypertreeIndex record.digest) = kp))).map (fun record => wotsOfDigest record.lowerDigest)

def upperExposureWords (records : List C10SigningRecord) (kp : ℕ) : List WotsWord :=
  (records.filter (fun record => decide
    (hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest)) = kp))).map
      (fun record => wotsOfDigest record.upperDigest)

theorem mem_lower_exposure_words (records : List C10SigningRecord) (tree kp : ℕ) (word : WotsWord) :
    word ∈ lowerExposureWords records tree kp ↔
      ∃ record ∈ records, hypertreeParent (hypertreeIndex record.digest) = tree ∧
        hypertreeLeaf (hypertreeIndex record.digest) = kp ∧ wotsOfDigest record.lowerDigest = word := by
  simp only [lowerExposureWords, List.mem_map, List.mem_filter, decide_eq_true_eq, and_assoc]

theorem mem_upper_exposure_words (records : List C10SigningRecord) (kp : ℕ) (word : WotsWord) :
    word ∈ upperExposureWords records kp ↔
      ∃ record ∈ records, hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest)) = kp ∧
        wotsOfDigest record.upperDigest = word := by
  simp only [upperExposureWords, List.mem_map, List.mem_filter, decide_eq_true_eq, and_assoc]

theorem lower_exposure_words_accepted_uniform (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (tree kp : ℕ) :
    (∀ word ∈ lowerExposureWords records tree kp, wotsAccept word = true) ∧
      (∀ first ∈ lowerExposureWords records tree kp,
        ∀ second ∈ lowerExposureWords records tree kp, first = second) := by
  constructor
  · intro word member
    obtain ⟨record, present, _, _, equal⟩ := (mem_lower_exposure_words records tree kp word).mp member
    obtain ⟨_, _, valid⟩ := exposure_history_record_member encode table cfg entries records history record present
    exact equal ▸ valid.lower_accepted
  · intro first one second two
    obtain ⟨a, amem, atree, aleaf, aword⟩ := (mem_lower_exposure_words records tree kp first).mp one
    obtain ⟨b, bmem, btree, bleaf, bword⟩ := (mem_lower_exposure_words records tree kp second).mp two
    have same := exposure_history_lower_word_eq encode table cfg entries records history a b amem bmem
      (atree.trans btree.symm) (aleaf.trans bleaf.symm)
    exact aword.symm.trans (same.trans bword)

theorem upper_exposure_words_accepted_uniform (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (kp : ℕ) :
    (∀ word ∈ upperExposureWords records kp, wotsAccept word = true) ∧
      (∀ first ∈ upperExposureWords records kp, ∀ second ∈ upperExposureWords records kp, first = second) := by
  constructor
  · intro word member
    obtain ⟨record, present, _, equal⟩ := (mem_upper_exposure_words records kp word).mp member
    obtain ⟨_, _, valid⟩ := exposure_history_record_member encode table cfg entries records history record present
    exact equal ▸ valid.upper_accepted
  · intro first one second two
    obtain ⟨a, amem, aleaf, aword⟩ := (mem_upper_exposure_words records kp first).mp one
    obtain ⟨b, bmem, bleaf, bword⟩ := (mem_upper_exposure_words records kp second).mp two
    have same := exposure_history_upper_word_eq encode table cfg entries records history a b amem bmem
      (aleaf.trans bleaf.symm)
    exact aword.symm.trans (same.trans bword)

theorem lower_exposure_minimum_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (tree kp : ℕ)
    (word : WotsWord) (accepted : wotsAccept word = true) :
    (∃ record ∈ records, hypertreeParent (hypertreeIndex record.digest) = tree ∧
      hypertreeLeaf (hypertreeIndex record.digest) = kp ∧ word = wotsOfDigest record.lowerDigest) ∨
      ∃ i, (word i).val < wotsExposureMinimum (lowerExposureWords records tree kp) i := by
  obtain ⟨priorAccepted, uniform⟩ := lower_exposure_words_accepted_uniform encode table cfg entries records history tree kp
  rcases wots_accepted_exposure_comparison (lowerExposureWords records tree kp) word accepted priorAccepted uniform with
    ⟨prior, member, same⟩ | earlier
  · obtain ⟨record, present, treeEq, leafEq, wordEq⟩ := (mem_lower_exposure_words records tree kp prior).mp member
    exact Or.inl ⟨record, present, treeEq, leafEq, same.trans wordEq.symm⟩
  · exact Or.inr earlier

theorem upper_exposure_minimum_comparison (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (entries : List C10Exposure) (records : List C10SigningRecord)
    (history : C10SigningHistory encode table cfg entries records) (kp : ℕ)
    (word : WotsWord) (accepted : wotsAccept word = true) :
    (∃ record ∈ records, hypertreeLeaf (hypertreeParent (hypertreeIndex record.digest)) = kp ∧
      word = wotsOfDigest record.upperDigest) ∨
      ∃ i, (word i).val < wotsExposureMinimum (upperExposureWords records kp) i := by
  obtain ⟨priorAccepted, uniform⟩ := upper_exposure_words_accepted_uniform encode table cfg entries records history kp
  rcases wots_accepted_exposure_comparison (upperExposureWords records kp) word accepted priorAccepted uniform with
    ⟨prior, member, same⟩ | earlier
  · obtain ⟨record, present, leafEq, wordEq⟩ := (mem_upper_exposure_words records kp prior).mp member
    exact Or.inl ⟨record, present, leafEq, same.trans wordEq.symm⟩
  · exact Or.inr earlier

end
end C10Probability
