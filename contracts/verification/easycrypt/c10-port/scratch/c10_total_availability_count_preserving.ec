require import AllCore List Distr IntDiv StdBigop RadixEncoding.
require import C10RawOracle C10RawGrind C10Counter C10Bytes.
require import PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
import Bigint.
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawWots RawCountRecorded PersistentGrind ByteSession.
require import MemoRejectCompletion WotsRejectDomain.
require import RawWots WotsPhysicalFailure.

module ControlledTotalAvailability (O : PreparationOracle) = {
  proc count(seed : raw_input, layer tree kp : int, message : raw_input) : (int * digest) option = {
    var i, d, result;
    i <- 0; result <- None;
    while (i < signing_budget /\ result = None) {
      d <@ O.hash(seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 i);
      if (count_accepts d) { result <- Some (i,d); }
      i <- i+(2-1);
    }
    return result;
  }
  proc chain(seed : raw_input, layer tree kp index : int, current : raw_input, start stop : int) : raw_input = {
    var j, d;
    j <- start;
    while (j < stop) {
      d <@ O.hash(seed ++ address layer tree 0 kp index j 0 ++ pad current);
      current <- node d; j <- j+1;
    }
    return current;
  }
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
      result <- Some (sigma,(oget accepted).`1);
    }
    return result;
  }
  proc recover(seed : raw_input, layer tree kp : int, message : raw_input, sigma : raw_input list, count : int) : raw_input = {
    var d, result, i, current, elements;
    d <@ O.hash(seed ++ address layer tree 0 kp 0 0 0 ++ pad message ++ be 32 count);
    result <- nseq 16 0;
    if (count_accepts d) {
      i <- 0; elements <- [];
      while (i < 43) {
        current <@ chain(seed,layer,tree,kp,i,nth (nseq 16 0) sigma i,RadixEncoding.digit 3 d i,7);
        elements <- rcons elements (pad current); i <- i+1;
      }
      d <@ O.hash(seed ++ address layer tree 1 kp 0 0 0 ++ flatten elements);
      result <- node d;
    }
    return result;
  }
}.

lemma checked :
  equiv[ControlledTotalAvailability(PreparationView(Physical)).count ~ RawWots(PreparationView(Physical)).count :
    ={arg,glob Physical,glob Shared} ==> ={res,glob Physical,glob Shared}].
proof.
  proc; while (={seed,layer,tree,kp,message,i,result,glob Physical,glob Shared}).
  + wp; call (_ : ={glob Physical,glob Shared}); first by sim.
    auto => />.
  auto => />.
qed.

lemma consumer_checked seed0 layer0 tree0 kp0 message0 :
  hoare[ControlledTotalAvailability(PreparationView(Physical)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 ==>
    res=None => forall j, 0<=j<signing_budget => exists d,
      Shared.history.[wots_count_input seed0 layer0 tree0 kp0 message0 j]=Some d /\ !count_accepts d].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    0<=i<=signing_budget /\ (result=None => forall j, 0<=j<i => exists d,
      Shared.history.[wots_count_input seed0 layer0 tree0 kp0 message0 j]=Some d /\ !count_accepts d)).
  + exists* i, Shared.history; elim* => i0 h0; wp.
    call (physical_hash_history h0 (wots_count_input seed0 layer0 tree0 kp0 message0 i0)).
    auto; rewrite /wots_count_input /extends; smt().
  auto; smt().
qed.
