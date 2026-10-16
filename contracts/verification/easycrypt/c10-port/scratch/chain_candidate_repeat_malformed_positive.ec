require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount NodeVectorMass ChainCandidateMass.

lemma checked : size (chain_variable_nodes [[];[]])=2.
proof.
  have h : size (chain_variable_nodes [[];[]])=2 by rewrite /chain_variable_nodes /=; smt(size_nseq).
  exact h.
qed.
