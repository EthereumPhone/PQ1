require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount NodeVectorMass ChainCandidateMass.

lemma checked : mem (chain_candidate_cover [nseq 16 7]) (nseq 16 7).
proof.
  have h : mem (chain_candidate_cover [nseq 16 7]) (nseq 16 7) by apply chain_candidate_cover_mem; smt().
  exact h.
qed.
