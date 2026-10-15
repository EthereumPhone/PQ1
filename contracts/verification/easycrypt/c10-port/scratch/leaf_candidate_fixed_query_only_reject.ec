require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen LeafCommitmentHybrid.
require import LeafCandidateCount.

lemma checked q :
  hoare[Independent.hash : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof.
  exact (leaf_variable_hash_fixed q).
qed.
