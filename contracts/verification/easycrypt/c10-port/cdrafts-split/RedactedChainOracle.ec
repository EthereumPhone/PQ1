(* Adaptive opening can be redacted because success requires an unopened selected cut. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen WotsReference.
require import ChainValueView ChainStageSampling CachedChainOracle.

module ChainRedaction = { var opened : bool }.
module RedactedChainPrefix = {
  proc hash = Independent.hash
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail=wots_key ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index) {
      ChainRedaction.opened <- true; d <- nseq 256 false;
    } else { d <@ Independent.derive(tail); }
    return d;
  }
}.
module RedactedCachedChain = {
  proc hash = Independent.hash
  proc derive = RedactedChainPrefix.derive
  proc value(seed : raw_input, layer tree kp index stop : int) : raw_input = {
    var result;
    if ((seed,layer,tree,kp,index)=(ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index) /\
        0<=stop<=7) {
      if (stop<=ChainCut.cut) { ChainRedaction.opened <- true; result <- nseq 16 0; }
      else { result <- nth (nseq 16 0) ChainStage.values stop; }
    } else {
      result <@ ConcreteChain(RedactedChainPrefix).value(seed,layer,tree,kp,index,stop);
    }
    return result;
  }
}.

lemma redacted_chain_derive_lossless : islossless RedactedChainPrefix.derive.
proof. proc; if; auto; call independent_derive_ll; auto. qed.
lemma redacted_chain_value_lossless : islossless RedactedCachedChain.value.
proof.
  proc; if.
  + if; auto.
  call (concrete_chain_value_lossless RedactedChainPrefix independent_hash_ll redacted_chain_derive_lossless); auto.
qed.

lemma redacted_chain_derive_coupling :
  equiv [ChainObservedPrefix(Independent).derive ~ RedactedChainPrefix.derive :
    ={arg,glob Independent,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    !ChainRevelation.opened{1} /\ !ChainRedaction.opened{2} ==>
    if ChainRedaction.opened{2} then ChainRevelation.opened{1}
    else ={res,glob Independent} /\ !ChainRevelation.opened{1}].
proof.
  proc; if{2}.
  + wp; call{1} independent_derive_ll; auto; smt().
  wp; call (_ : ={glob Independent}); first by sim.
  auto; smt().
qed.
