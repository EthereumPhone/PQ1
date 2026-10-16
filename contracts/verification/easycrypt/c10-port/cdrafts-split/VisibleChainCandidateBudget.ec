(* Filter the unchanged candidate list; retain every output slot and charge both fixed values in the mass lemma. *)
require import AllCore List Distr DList.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion FullPrefix.
require import FullSession ByteSession ExposureLog ClientQueryLog.
require import ChainValueView ChainSessionView ChainByteCandidates RedactedChainOracle ChainVariableSessionCost.
require import RawKeygen LeafCandidateCount ChainCandidateMass.
require import ChainTableInstallation VisibleChainInstallation ChainVisibleGuess.

lemma chain_variable_byte_candidates_cost
  (A <: ByteClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[ChainByteCandidates(A,RedactedCachedChain).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs /\ Independent.queries=[] ==>
    leaf_variable_count Independent.queries<=chain_candidate_budget qr qs /\ size res<=86].
proof.
  move=> hr hs; proc; wp; call (chain_variable_context_cost (ByteLift(A)) qr qs hr hs).
  auto; rewrite /chain_candidate_budget; smt(wots_output_candidates_size).
qed.
lemma visible_chain_candidate_budget
  (A <: ByteClient {-FullSession,-Independent,-ExposureLog,-ClientQueryLog,-FullLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare[VisibleChainCandidates(ChainByteCandidates(A)).run :
    FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size (chain_variable_nodes res)<=chain_candidate_budget qr qs+86].
proof.
  move=> hr hs; proc; wp.
  call (chain_variable_byte_candidates_cost A qr qs hr hs).
  wp; inline VisibleChainInstall.run VisibleChainStep.run Independent.init.
  auto; smt(chain_variable_nodes_query_outputs).
qed.
