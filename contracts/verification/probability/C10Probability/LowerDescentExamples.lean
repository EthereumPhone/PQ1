import C10Probability.LowerDescent
import C10Probability.ExposureExamples
import C10Probability.WotsOpeningExamples

/-! Necessary-premise and address-boundary witnesses. Constant populated
caches demonstrate possible accepted-word collisions, not their probability
in the initialized game. Synthetic records test coordinates only and are not
asserted to be actual signing histories. -/
namespace C10Probability
noncomputable section
set_option maxRecDepth 4096

theorem count_distinct_node_messages_distinct_inputs :
    wotsRecoverCountInput [] 1 0 3 (nodeValueBytes 0) 7 ≠
      wotsRecoverCountInput [] 1 0 3 (nodeValueBytes 1) 9 := by
  intro equal
  have impossible := wots_count_input_node_eq [] 1 0 3 0 1 7 9 equal
  contradiction

theorem count_equal_accepted_words_need_collision_branch :
    let cache : Memo ByteKey Digest := fun _ => some recoveryAcceptedDigest
    cache (wotsRecoverCountInput [] 1 0 3 (nodeValueBytes 0) 7) = some recoveryAcceptedDigest ∧
    cache (wotsRecoverCountInput [] 1 0 3 (nodeValueBytes 1) 9) = some recoveryAcceptedDigest ∧
    wotsAccept (wotsOfDigest recoveryAcceptedDigest) = true ∧
    AcceptedWotsCollision cache ∧ (0 : Randomizer) ≠ 1 := by
  refine ⟨rfl, rfl, recovery_digest_accepted, ?_, by decide⟩
  exact ⟨_, _, recoveryAcceptedDigest, recoveryAcceptedDigest, rfl, rfl,
    recovery_digest_accepted, rfl, count_distinct_node_messages_distinct_inputs⟩

theorem count_repeated_same_input_is_not_collision :
    AcceptedCollisionFree wotsOfDigest wotsAccept
      (fun key : ByteKey => if key = [] then some recoveryAcceptedDigest else none) := by
  intro key other value reply left right _ _
  have first : key = [] := by
    by_contra absent
    simp [absent] at left
  have second : other = [] := by
    by_contra absent
    simp [absent] at right
  exact first.trans second.symm

theorem count_nat_encoding_can_wrap :
    wotsRecoverCountInput [] 1 0 3 (nodeValueBytes 1) 0 =
      wotsRecoverCountInput [] 1 0 3 (nodeValueBytes 1) (2 ^ 256) ∧
      (0 : ℕ) ≠ 2 ^ 256 := by
  decide +kernel

theorem descent_upper_address_allows_distinct_lower_leaves :
    let first := exposureRecordFixture 513 1 2
    let second := exposureRecordFixture 514 3 4
    hypertreeLeaf (hypertreeParent (hypertreeIndex first.digest)) =
      hypertreeLeaf (hypertreeParent (hypertreeIndex second.digest)) ∧
    hypertreeParent (hypertreeIndex first.digest) = hypertreeParent (hypertreeIndex second.digest) ∧
    hypertreeLeaf (hypertreeIndex first.digest) ≠ hypertreeLeaf (hypertreeIndex second.digest) := by
  decide +kernel

theorem descent_same_lower_leaf_does_not_bind_tree :
    let first := exposureRecordFixture 513 1 2
    let second := exposureRecordFixture 1025 3 4
    hypertreeLeaf (hypertreeIndex first.digest) = hypertreeLeaf (hypertreeIndex second.digest) ∧
    hypertreeParent (hypertreeIndex first.digest) ≠ hypertreeParent (hypertreeIndex second.digest) := by
  decide +kernel

theorem descent_lower_empty_history_retains_endpoint :
    lowerExposureWords exposureRecordFixtures 1 3 = [] ∧
      wotsExposureMinimum (lowerExposureWords exposureRecordFixtures 1 3) 0 = 7 := by
  decide +kernel

end
end C10Probability
