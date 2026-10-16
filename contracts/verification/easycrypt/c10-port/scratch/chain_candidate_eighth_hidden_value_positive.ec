require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount NodeVectorMass ChainCandidateMass.

lemma checked : node_vector_hit [nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 false] [node (nseq 256 false)].
proof.
  have h : node_vector_hit [nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 true; nseq 256 false] [node (nseq 256 false)] by rewrite /node_vector_hit /=; smt().
  exact h.
qed.
