require import AllCore List StdOrder.
require import DistinctWitnessWords.


lemma checked : distinct_witness_words 3 0 3=[].
proof.
  have h : distinct_witness_words 3 0 3=[].
  + apply distinct_witness_words_insufficient; smt().
  exact h.
qed.
