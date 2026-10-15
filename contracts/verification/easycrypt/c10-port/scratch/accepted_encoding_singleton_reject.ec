require import AllCore List Distr FMap StdOrder.
require import C10RawOracle RawWots AcceptedEncodingPool.

lemma checked (d : digest) : accepted_encoding_pool_collision [d].
proof.
  have h : !accepted_encoding_pool_collision [d].
  + rewrite /accepted_encoding_pool_collision /accepted_encoding_words /=; case (count_accepts d); by [].
  exact h.
qed.
