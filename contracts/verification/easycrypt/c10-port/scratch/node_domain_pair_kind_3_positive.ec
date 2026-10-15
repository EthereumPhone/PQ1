require import AllCore List FMap.
require import C10RawOracle RawKeygen NodeQueryDomain DomainQueryCount.

lemma checked : node_query (nseq 32 0 ++ address 0 0 3 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0)).
proof.
  have h : node_query (nseq 32 0 ++ address 0 0 3 0 0 0 0 ++ pad (nseq 16 0) ++ pad (nseq 16 0)) by apply node_query_pair => //; smt(size_nseq node_query_fors_kind).
  exact h.
qed.
