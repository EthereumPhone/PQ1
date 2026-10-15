require import AllCore List StdOrder.
require import DistinctWitnessWords.


lemma checked : size (distinct_witness_words 4 1 2)=6.
proof.
  have h : size (distinct_witness_words 4 1 2)=6.
  + rewrite distinct_witness_words_size 1:/# 1:/# (falling_step 3 1) 1:/# (falling_step 2 0) 1:/# falling_zero /=.
    by [].
  exact h.
qed.
