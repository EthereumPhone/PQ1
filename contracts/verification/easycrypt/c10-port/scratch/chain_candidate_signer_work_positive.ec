require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrind RoleGrindCost.
require import RawForest RawForestCost RawLayer RawLayerCost RawSigner.
require import ChainValueView ChainLayerView ChainSignerView RedactedChainOracle ChainVariableBasicCost ChainVariableWotsCost ChainVariableMerkleCost ChainVariableForestCost ChainVariableLayerCost.
require import LeafCandidateCount LeafGrindingCandidates.
require import ChainVariableSignerCost.

lemma checked q :
  hoare[ChainSigner(RedactedCachedChain).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+364892].
proof.
  exact (chain_variable_signer_sign_public_cost q).
qed.
