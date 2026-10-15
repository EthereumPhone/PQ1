require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen LeafCommitmentHybrid.
require import LeafCandidateCount.

lemma checked prefix counter :
  leaf_suffix_candidate (prefix ++ (nseq 28 0 ++ counter)) = nseq 16 0.
proof.
  exact (leaf_suffix_zero_counter prefix counter).
qed.
