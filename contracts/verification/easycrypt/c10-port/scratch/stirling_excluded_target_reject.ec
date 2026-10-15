require import AllCore List StdOrder.
require import DistinctWitnessWords.


lemma checked : mem (distinct_witness_words 4 1 1) [1].
proof.
  have h : !mem (distinct_witness_words 4 1 1) [1].
  + by rewrite distinct_witness_words_member 1:/# /=.
  exact h.
qed.
