require import AllCore List Distr FMap StdOrder.
require import C10RawOracle RawWots AcceptedEncodingPool.

lemma checked : accepted_encoding_pool_collision [].
proof.
  have h : !accepted_encoding_pool_collision [] by rewrite /accepted_encoding_pool_collision /accepted_encoding_words.
  exact h.
qed.
