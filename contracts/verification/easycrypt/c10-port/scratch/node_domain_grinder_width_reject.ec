require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import DomainQueryCount NodeQueryDomain DomainShuffleCost ClientGuessCandidates.
require import DomainWotsCost.

lemma checked q :
  hoare[RawWots(PreparationView(Independent)).count : size seed=32 /\
    node_query_count Independent.queries<=q ==> node_query_count Independent.queries<=q].
proof.
  exact (domain_count_cost q).
qed.
