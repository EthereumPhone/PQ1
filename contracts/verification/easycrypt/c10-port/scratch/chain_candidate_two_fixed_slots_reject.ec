require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount NodeVectorMass ChainCandidateMass.

lemma checked : size (chain_candidate_cover [])=1.
proof.
  have h : size (chain_candidate_cover [])=2 by rewrite chain_candidate_cover_size /chain_variable_nodes /=.
  exact h.
qed.
