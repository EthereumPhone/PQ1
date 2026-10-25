require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle RawLayer.
require import ChainValueView ChainMerkleView ChainStageSampling CachedChainOracle ChainObserverProjection.
require import ObservedValueOpening ObservedKeygenOpening WrapperWotsPlan WrapperLayerPlan.

module WotsEarlyValueControl (O : ChainOracle) = {
  proc plan(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : wrapper_layer_plan option = {
    var built, subseed, signed, result, early;
    built <@ ChainMerkle(O).build(seed,layer,tree,leaf);
    early <@ O.value(seed,layer,tree,0,0,0);
    subseed <@ RawShuffle(PreparationView(ChainPrefix(O))).derive(shuffle,layer_label layer);
    signed <@ WrapperWotsPlan(ChainPrefix(O)).plan(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed<>None) {
      result <- Some ((oget signed).`1,(oget signed).`2,built.`1,built.`2);
    }
    return result;
  }
}.

