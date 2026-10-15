require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains C10Representation.
require import RawKeygen C10CallerInputBridge LeafCommitmentHybrid LeafCandidateCount.
require import LeafGrindingCandidates.

lemma checked prefix c : 0<=c<4294967296 =>
  !leaf_variable_query (prefix ++ be 32 c).
proof.
  exact (leaf_counter_candidate_fixed prefix c).
qed.
