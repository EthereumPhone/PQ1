require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawShuffle RawWots RawMerkle.
require import AllCore List Distr FMap IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import PreparedGrind KeygenExhaustion RObservedSigner RoleGrind.
require import RawWots RawLayer RawForest RawSigner RawCompositeWidths.
require import ByteSession RawByteValues RawCompositeBytes.
require import MemoRejectCompletion WotsRejectDomain WotsPhysicalFailure.
require import RawLayer WotsSignerFailure.

module ControlledTotalAvailability (O : PreparationOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input, sig : layer_signature) : raw_input = {
    var pk, root;
    pk <@ RawWots(O).recover(seed,layer,tree,leaf,message,sig.`1,sig.`2);
    root <@ RawMerkle(O).recover(seed,layer,tree,pk,leaf,sig.`3);
    return root;
  }
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : (layer_signature * raw_input) option = {
    var built, subseed, signed, sig, root, result;
    built <@ RawMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ RawShuffle(O).derive(shuffle,layer_label layer);
    signed <@ RawWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
      root <@ recover(seed,layer,tree,leaf,message,sig);
      result <- None;
    }
    return result;
  }
}.

