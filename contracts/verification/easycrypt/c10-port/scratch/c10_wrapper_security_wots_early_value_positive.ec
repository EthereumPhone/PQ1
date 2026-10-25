require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle RawLayer.
require import ChainValueView ChainMerkleView ChainStageSampling CachedChainOracle ChainObserverProjection.
require import ObservedValueOpening ObservedKeygenOpening WrapperWotsPlan WrapperLayerPlan.

module WotsEarlyValueControl (O : ChainOracle) = {
  proc plan(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : wrapper_layer_plan option = {
    var built, subseed, signed, result;
    built <@ ChainMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ RawShuffle(PreparationView(ChainPrefix(O))).derive(shuffle,layer_label layer);
    signed <@ WrapperWotsPlan(ChainPrefix(O)).plan(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed<>None) {
      result <- Some ((oget signed).`1,(oget signed).`2,built.`1,built.`2);
    }
    return result;
  }
}.

lemma wrapper_chain_layer_plan_unopened seed0 layer0 tree0 opened0 :
  hoare [WotsEarlyValueControl(ObservedChain(Independent)).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened=opened0].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  call (_ : true ==> true); first by trivial.
  call (observed_merkle_unopened seed0 layer0 tree0 opened0); auto.
qed.
