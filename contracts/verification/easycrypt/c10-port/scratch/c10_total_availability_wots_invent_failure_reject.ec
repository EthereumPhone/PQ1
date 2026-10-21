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

lemma checked seed0 layer0 tree0 kp0 message0 :
  hoare[ControlledTotalAvailability(PreparationView(Physical)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    size message0=16 /\ byte_values message0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; seq 1 : (accepted=None => wots_domain_exhausted seed0 signing_budget Shared.history).
  + call (physical_count_failure seed0 layer0 tree0 kp0 message0); auto.
  sp 1; if; last by auto; smt().
  wp; while true.
  + wp; call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.
