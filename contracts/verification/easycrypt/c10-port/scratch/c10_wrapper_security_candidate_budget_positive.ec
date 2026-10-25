require import WrapperWotsCandidateBudget.
(* The initialized adaptive wrapper pays for every admitted attempt, including
   refusal, while the final output contributes at most 86 WOTS candidates. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawSigner.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog.
require import ChainValueView RedactedChainOracle LeafCandidateCount LeafGrindingCandidates.
require import ChainVariableSignerCost ChainVariableSessionCost WrapperWotsCandidateCost.
require import WrapperWotsReleaseSession WrapperWotsChainContext.

op wrapper_wots_candidate_budget qr qs = 155135+qr+qs*727934+771.
op wrapper_wots_candidate_accounting q calls limit signs signlimit queries =
  0<=calls<=limit /\ 0<=signs<=signlimit /\ queries<=q+calls+727934*signs.


lemma wrapper_wots_context_candidate_cost
  (A <: WrapperClient {-WrapperSession,-Independent,-ExposureLog,-ClientQueryLog,-WrapperLimits,-KeygenInputs}) qr qs :
  0<=qr => 0<=qs =>
  hoare [WrapperChainWotsContext(A,RedactedCachedChain).run :
    WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs /\ leaf_variable_count Independent.queries<=0 ==>
    leaf_variable_count Independent.queries<=wrapper_wots_candidate_budget qr qs].
proof. move=> hr hs; exact (WrapperWotsCandidateBudget.wrapper_wots_context_candidate_cost A qr qs hr hs). qed.
