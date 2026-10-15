require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount LeafCandidateMass LeafGrindingCandidates.

lemma checked : leaf_variable_query ([] ++ be 32 4294967295).
proof.
  have h : !leaf_variable_query ([] ++ be 32 4294967295) by apply leaf_counter_candidate_fixed; smt().
  exact h.
qed.
