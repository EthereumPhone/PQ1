require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount LeafCandidateMass LeafGrindingCandidates.

lemma checked : mem (leaf_reduced_candidates [] [nseq 16 7]) (nseq 16 7).
proof.
  have h : mem (leaf_reduced_candidates [] [nseq 16 7]) (nseq 16 7) by rewrite /leaf_reduced_candidates /=; smt().
  exact h.
qed.
