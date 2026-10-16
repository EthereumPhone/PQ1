require import AllCore List.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RoleGrindCost.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView RedactedChainOracle ChainVariableKeygenCost ChainVariableSignerCost.
require import LeafCandidateCount LeafGrindingCandidates.
require import ChainVariableSessionCost.

lemma checked (A <: FullClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ChainQueryContext(A,RedactedCachedChain).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ leaf_variable_count Independent.queries<=0 ==>
    leaf_variable_count Independent.queries<=155135+qr+qs*(364892)+771].
proof.
  move=> hr hs; exact (chain_variable_context_cost A qr qs hr hs).
qed.
