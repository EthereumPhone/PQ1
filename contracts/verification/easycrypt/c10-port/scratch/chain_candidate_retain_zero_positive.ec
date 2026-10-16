require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount NodeVectorMass ChainCandidateMass.

lemma checked : mem (chain_candidate_cover []) (nseq 16 0).
proof.
  have h : mem (chain_candidate_cover []) (nseq 16 0) by rewrite /chain_candidate_cover /chain_variable_nodes /=; smt().
  exact h.
qed.
