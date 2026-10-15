require import AllCore List StdOrder.
require import DistinctWitnessWords.


lemma checked : distinct_witness_words 0 0 0=[].
proof.
  have h : distinct_witness_words 0 0 0=[[]].
  + by rewrite /distinct_witness_words distinct_words_zero.
  exact h.
qed.
