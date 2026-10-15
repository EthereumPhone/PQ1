require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains C10Representation.
require import RawKeygen C10CallerInputBridge LeafCommitmentHybrid LeafCandidateCount.
require import LeafGrindingCandidates.

lemma checked seed root random message :
  leaf_variable_query (hmsg_input seed root random message).
proof.
  exact (leaf_hmsg_candidate_fixed seed root random message).
qed.
