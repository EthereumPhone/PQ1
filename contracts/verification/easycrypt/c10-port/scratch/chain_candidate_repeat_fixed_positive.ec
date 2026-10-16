require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount NodeVectorMass ChainCandidateMass.

lemma checked : size (chain_variable_nodes [nseq 16 0; nseq 16 255; nseq 16 0])=0.
proof.
  have h : size (chain_variable_nodes [nseq 16 0; nseq 16 255; nseq 16 0])=0 by rewrite /chain_variable_nodes /=; smt().
  exact h.
qed.
