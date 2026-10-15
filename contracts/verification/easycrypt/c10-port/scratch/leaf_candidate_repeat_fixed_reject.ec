require import AllCore List FMap.
require import C10RawOracle C10Randomizer RawKeygen LeafCommitmentHybrid LeafCandidateCount LeafCandidateMass LeafGrindingCandidates.

lemma checked : leaf_variable_count [pad (nseq 16 0); pad (nseq 16 255); pad (nseq 16 0)]=3.
proof.
  have h : leaf_variable_count [pad (nseq 16 0); pad (nseq 16 255); pad (nseq 16 0)]=0 by have hz := padded_leaf_suffix [] (nseq 16 0); have hf := padded_leaf_suffix [] (nseq 16 255);
  move: hz hf; rewrite /= !size_nseq /= => hz hf;
  rewrite /leaf_variable_count /leaf_variable_query /=; smt().
  exact h.
qed.
