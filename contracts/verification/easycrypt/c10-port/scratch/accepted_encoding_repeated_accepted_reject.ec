require import AllCore List Distr FMap StdOrder.
require import C10RawOracle RawWots AcceptedEncodingPool.

lemma checked (d : digest) : count_accepts d => !accepted_encoding_pool_collision [d;d].
proof.
  move=> hd.
  have h : accepted_encoding_pool_collision [d;d] by rewrite /accepted_encoding_pool_collision /accepted_encoding_words /= hd /=.
  exact h.
qed.
