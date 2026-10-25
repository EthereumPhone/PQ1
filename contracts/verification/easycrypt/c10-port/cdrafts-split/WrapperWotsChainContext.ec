(* Initialized chain-interface wrapper game and its actual output candidates.
   Client admission and the external signature ledger remain unchanged. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog WrapperQueryDriver.
require import ChainValueView ChainSessionView ChainByteCandidates WrapperWotsReleaseSession WrapperWotsReleaseContext.

module WrapperChainWotsContext (A : WrapperClient) (O : ChainOracle) =
  WrapperWotsReleaseContext(A,ChainPrefix(O),O).

module WrapperChainWotsCandidates (A : WrapperByteClient) (O : ChainOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ WrapperChainWotsContext(WrapperByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- wots_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.
module WrapperOriginalWotsCandidates (A : WrapperByteClient) (O : PrefixOracle) = {
  proc run() : raw_input list = {
    var accepted, outputs;
    accepted <@ WrapperQueryContext(WrapperByteLift(A),O).run();
    outputs <- [];
    if (accepted) { outputs <- wots_output_candidates ClientQueryLog.output.`2; }
    return outputs;
  }
}.

lemma wrapper_wots_chain_context_projection
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [WrapperQueryContext(A,Independent).run ~ WrapperChainWotsContext(A,ConcreteChain(Independent)).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity ConcreteWrapperWotsReleaseContext(A,Independent).run
    (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
      ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory})
    (={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
      ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,glob Independent}) => //.
  + smt().
  + exact (wrapper_wots_release_context_projection A).
  by sim.
qed.

lemma wrapper_wots_candidates_projection
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  equiv [WrapperOriginalWotsCandidates(A,Independent).run ~ WrapperChainWotsCandidates(A,ConcreteChain(Independent)).run :
    ={glob A,glob Independent,glob WrapperLimits,glob KeygenInputs} ==>
    ={res,glob A,glob WrapperSession,glob ExposureLog,glob ClientQueryLog,Independent.rawhistory,Independent.secrethistory}].
proof. proc; wp; call (wrapper_wots_chain_context_projection (WrapperByteLift(A))); auto. qed.

lemma wrapper_wots_candidates_count
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog})
  (O <: ChainOracle {-A,-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog}) :
  hoare [WrapperChainWotsCandidates(A,O).run : true ==> size res<=86].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto; smt(wots_output_candidates_size).
qed.
