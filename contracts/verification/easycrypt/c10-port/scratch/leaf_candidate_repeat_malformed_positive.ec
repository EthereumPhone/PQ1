require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount LeafCandidateMass LeafGrindingCandidates.

lemma checked : leaf_variable_count [[];[]]=2.
proof.
  have h : leaf_variable_count [[];[]]=2 by rewrite /leaf_variable_count /leaf_variable_query /leaf_suffix_candidate /=; smt(size_nseq).
  exact h.
qed.
