require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RoleGrind RoleGrindCost RawShuffle RawWots RedactedChainOracle ChainValueView.
require import LeafCandidateCount LeafGrindingCandidates.
require import ChainVariableBasicCost.

lemma checked q :
  hoare[RedactedCachedChain.value :
    leaf_variable_count Independent.queries<=q /\ 0<=stop<=7 ==>
    leaf_variable_count Independent.queries<=q+7].
proof.
  exact (chain_variable_cached_value_cost q).
qed.
