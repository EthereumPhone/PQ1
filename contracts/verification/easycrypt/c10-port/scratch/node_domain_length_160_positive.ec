require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.

lemma checked : !node_query (nseq 160 0).
proof.
  have h : !node_query (nseq 160 0) by rewrite /node_query size_nseq /=.
  exact h.
qed.
