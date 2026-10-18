import C10Probability.C10SigningRecord
import C10Probability.ForestStability

/-! Equal logical WOTS addresses identify equal actual signed messages in
successful C10 executions. Lower addresses identify one complete forest;
upper addresses identify one lower-layer tree. No address injectivity across
arbitrary encoded keys, collision exclusion or freshness premise is used. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem hypertree_equal_lower_coordinates (first second : ℕ)
    (tree : hypertreeParent first = hypertreeParent second)
    (leaf : hypertreeLeaf first = hypertreeLeaf second) : first = second := by
  have one := hypertree_coordinate_split first
  have two := hypertree_coordinate_split second
  omega

theorem hypertree_top_leaf_eq_parent (digest : Digest) :
    hypertreeLeaf (hypertreeParent (hypertreeIndex digest)) =
      hypertreeParent (hypertreeIndex digest) := by
  exact Nat.mod_eq_of_lt (hypertree_first_parent_bound digest)

theorem c10_record_lower_message_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (firstEntry secondEntry : C10Exposure)
    (first second : C10SigningRecord)
    (one : C10SigningRecordValid encode table cfg firstEntry first)
    (two : C10SigningRecordValid encode table cfg secondEntry second)
    (tree : hypertreeParent (hypertreeIndex first.digest) = hypertreeParent (hypertreeIndex second.digest))
    (leaf : hypertreeLeaf (hypertreeIndex first.digest) = hypertreeLeaf (hypertreeIndex second.digest)) :
    first.forest.pk = second.forest.pk := by
  have indexEq := hypertree_equal_lower_coordinates _ _ tree leaf
  have other := two.forest
  rw [← indexEq] at other
  exact replay_forest_sign_pk_eq encode table cfg.seed (hypertreeIndex first.digest)
    first.digest second.digest firstEntry.request.shuffle secondEntry.request.shuffle
    first.forest second.forest one.forest other

theorem c10_record_upper_message_eq (encode : WotsQuery → K) (table : Memo K Digest)
    (cfg : C10SessionConfig) (firstEntry secondEntry : C10Exposure)
    (first second : C10SigningRecord)
    (one : C10SigningRecordValid encode table cfg firstEntry first)
    (two : C10SigningRecordValid encode table cfg secondEntry second)
    (leaf : hypertreeLeaf (hypertreeParent (hypertreeIndex first.digest)) =
      hypertreeLeaf (hypertreeParent (hypertreeIndex second.digest))) :
    first.middle = second.middle := by
  have parentEq : hypertreeParent (hypertreeIndex first.digest) =
      hypertreeParent (hypertreeIndex second.digest) := by
    simpa only [hypertree_top_leaf_eq_parent] using leaf
  have other := two.lower
  rw [← parentEq] at other
  exact replay_layer_sign_roots_eq encode table cfg.seed 0
    (hypertreeParent (hypertreeIndex first.digest))
    (hypertreeLeaf (hypertreeIndex first.digest)) (hypertreeLeaf (hypertreeIndex second.digest))
    first.forest.pk second.forest.pk firstEntry.request.shuffle secondEntry.request.shuffle
    cfg.wTrials cfg.wTrials cfg.wBound cfg.wBound first.lower second.lower first.middle second.middle
    one.lower other (hypertree_leaf_bound _) (hypertree_leaf_bound _)

end
end C10Probability
