require import AllCore List Distr IntDiv StdBigop RadixEncoding.
require import C10RawOracle C10RawGrind C10Counter C10Bytes.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
import Bigint.
require import AllCore List Distr FMap IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import PreparedGrind KeygenExhaustion RObservedSigner RoleGrind.
require import RawWots RawLayer RawForest RawSigner RawCompositeWidths.
require import ByteSession RawByteValues RawCompositeBytes.
require import MemoRejectCompletion WotsRejectDomain WotsPhysicalFailure.
require import RawWots WotsSignerFailure.

module ControlledTotalAvailability (O : PreparationOracle) = {
  proc count = RawWots(O).count
  proc chain = RawWots(O).chain
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, result, order, step, i, d, current, sigma;
    accepted <@ count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted <> None) {
      sigma <- nseq 43 (nseq 16 0);
      order <@ RawShuffle(O).permutation(shuffle,43);
      step <- 0;
      while (step < 43) {
        i <- nth 0 order step;
        d <@ O.wots(wots_tail layer tree kp i);
        current <@ chain(seed,layer,tree,kp,i,node d,0,RadixEncoding.digit 3 (oget accepted).`2 i);
        sigma <- put sigma i current; step <- step+1;
      }
      result <- None;
    }
    return result;
  }
}.

