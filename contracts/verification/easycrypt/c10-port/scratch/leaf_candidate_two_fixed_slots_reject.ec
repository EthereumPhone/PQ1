require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount LeafCandidateMass LeafGrindingCandidates.

lemma checked : size (leaf_reduced_candidates [] [])=1.
proof.
  have h : size (leaf_reduced_candidates [] [])=2 by rewrite leaf_reduced_candidates_size /leaf_variable_count /=.
  exact h.
qed.
