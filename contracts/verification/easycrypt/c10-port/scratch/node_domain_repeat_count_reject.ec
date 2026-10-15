require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.

lemma checked : node_query_count [[];[]]=1.
proof.
  have h : node_query_count [[];[]]=2 by rewrite /node_query_count /node_query /=.
  exact h.
qed.
