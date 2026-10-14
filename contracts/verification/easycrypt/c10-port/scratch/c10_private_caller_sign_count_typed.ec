(* Common private inputs in the actual WOTS leaf and signing callers.
   The same arbitrary oracle runs on both sides, including its full state.
   Signing composes the paired shuffle representation with exact order and
   oracle-state preservation; no concrete-SHA interpretation is asserted here. *)
require import AllCore List IntDiv RadixEncoding.
require import C10Bytes C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawLeafChains RawWotsFill RawShuffle ShuffleBytes ShuffleSwap.
require import C10Representation C10AddressInputBridge C10CallerInputBridge C10ShuffleBridge.


(* Partial correctness requires no losslessness premise on the shared oracle. *)

module CommonPrivateWots (O : PrefixOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input = {
    var i, d, current, elements;
    i <- 0; elements <- [];
    while (i < 43) {
      d <@ O.derive(wots_private_preimage [] layer tree kp i);
      current <@ CommonInputWots(PreparationView(O)).chain(seed,layer,tree,kp,i,node d,0,7);
      elements <- rcons elements current; i <- i+1;
    }
    d <@ O.hash(multi_preimage seed (address_words layer tree 1 kp 0 0 0) elements);
    return node d;
  }
  proc fill(seed : raw_input, layer tree kp : int, accepted : digest, shuffle : raw_input) : raw_input list = {
    var order, step, i, d, current, sigma;
    sigma <- nseq 43 (nseq 16 0);
    order <@ PairedShuffle(PreparationView(O)).permutation(shuffle,43);
    step <- 0;
    while (step < 43) {
      i <- nth 0 order step;
      d <@ O.derive(wots_private_preimage [] layer tree kp i);
      current <@ CommonInputWots(PreparationView(O)).chain(seed,layer,tree,kp,i,node d,0,digit 3 accepted i);
      sigma <- put sigma i current; step <- step+1;
    }
    return sigma;
  }
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, sigma, result;
    accepted <@ CommonInputWots(PreparationView(O)).count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted <> None) {
      sigma <@ fill(seed,layer,tree,kp,(oget accepted).`2,shuffle);
      result <- Some (sigma,(oget accepted).`1+1);
    }
    return result;
  }
}.







