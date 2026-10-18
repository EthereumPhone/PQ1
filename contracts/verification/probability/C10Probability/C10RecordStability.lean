import C10Probability.C10AddressStability
import C10Probability.WotsStability

/-! Every actual successful C10 exposure at one logical WOTS address has the
same accepted digest and returned component. Requests, randomizers, digests
and shuffles may differ. This is a final-cache functional statement, not a
freshness or secrecy statement. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem c10_record_lower_wots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (firstEntry secondEntry : C10Exposure)
    (first second : C10SigningRecord)
    (one : C10SigningRecordValid encode table cfg firstEntry first)
    (two : C10SigningRecordValid encode table cfg secondEntry second)
    (tree : hypertreeParent (hypertreeIndex first.digest) = hypertreeParent (hypertreeIndex second.digest))
    (leaf : hypertreeLeaf (hypertreeIndex first.digest) = hypertreeLeaf (hypertreeIndex second.digest)) :
    first.lower = second.lower ∧ first.lowerDigest = second.lowerDigest ∧ first.middle = second.middle := by
  have message := c10_record_lower_message_eq encode table cfg firstEntry secondEntry first second one two tree leaf
  have signed := two.lower
  have counted := two.lower_count
  rw [← tree, ← leaf, ← message] at signed counted
  obtain ⟨signature, root⟩ := replay_layer_sign_result_eq encode table cfg.seed 0
    (hypertreeParent (hypertreeIndex first.digest)) (hypertreeLeaf (hypertreeIndex first.digest))
    first.forest.pk firstEntry.request.shuffle secondEntry.request.shuffle cfg.wTrials cfg.wBound
    first.lower second.lower first.middle second.middle one.lower signed
  have pairEq := Option.some.inj (replay_program_unique _ table
    (some (first.lower.count, first.lowerDigest)) (some (second.lower.count, second.lowerDigest))
    one.lower_count counted)
  exact ⟨signature, congrArg Prod.snd pairEq, root⟩

theorem c10_record_upper_wots_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (firstEntry secondEntry : C10Exposure)
    (first second : C10SigningRecord)
    (one : C10SigningRecordValid encode table cfg firstEntry first)
    (two : C10SigningRecordValid encode table cfg secondEntry second)
    (leaf : hypertreeLeaf (hypertreeParent (hypertreeIndex first.digest)) =
      hypertreeLeaf (hypertreeParent (hypertreeIndex second.digest))) :
    first.upper = second.upper ∧ first.upperDigest = second.upperDigest ∧ first.top = second.top := by
  have message := c10_record_upper_message_eq encode table cfg firstEntry secondEntry first second one two leaf
  have signed := two.upper
  have counted := two.upper_count
  rw [← leaf, ← message] at signed counted
  obtain ⟨signature, root⟩ := replay_layer_sign_result_eq encode table cfg.seed 1 0
    (hypertreeLeaf (hypertreeParent (hypertreeIndex first.digest)))
    first.middle firstEntry.request.shuffle secondEntry.request.shuffle cfg.wTrials cfg.wBound
    first.upper second.upper first.top second.top one.upper signed
  have pairEq := Option.some.inj (replay_program_unique _ table
    (some (first.upper.count, first.upperDigest)) (some (second.upper.count, second.upperDigest))
    one.upper_count counted)
  exact ⟨signature, congrArg Prod.snd pairEq, root⟩

end
end C10Probability
