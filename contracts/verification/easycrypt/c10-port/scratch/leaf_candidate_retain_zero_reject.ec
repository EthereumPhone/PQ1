require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount LeafCandidateMass LeafGrindingCandidates.

lemma checked : !(mem (leaf_reduced_candidates [] []) (nseq 16 0)).
proof.
  have h : mem (leaf_reduced_candidates [] []) (nseq 16 0) by rewrite /leaf_reduced_candidates /=; smt().
  exact h.
qed.
