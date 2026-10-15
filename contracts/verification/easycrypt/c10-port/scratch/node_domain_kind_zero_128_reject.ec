require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.

lemma checked : node_query (nseq 32 0 ++ address 0 0 0 0 0 0 0 ++ pad (nseq 16 0) ++ be 32 0).
proof.
  have h : !node_query (nseq 32 0 ++ address 0 0 0 0 0 0 0 ++ pad (nseq 16 0) ++ be 32 0) by apply node_query_no_count; rewrite size_nseq /=.
  exact h.
qed.
