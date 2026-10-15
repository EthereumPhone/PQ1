require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import NodeQueryDomain IndependentWidths.
require import DomainQueryCount.

lemma checked q :
  hoare[Independent.hash : node_query_count Independent.queries<=q ==>
    node_query_count Independent.queries<=q].
proof.
  exact (domain_hash_nonnode q).
qed.
