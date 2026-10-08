(* Trusted WOTS construction exposes a requested chain position through one internal interface. *)
require import AllCore List RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.

module type ChainOracle = {
  proc hash(x : raw_input) : digest
  proc derive(tail : raw_input) : digest
  proc value(seed : raw_input, layer tree kp index stop : int) : raw_input
}.
module ChainPrefix (O : ChainOracle) = {
  proc hash = O.hash
  proc derive = O.derive
}.
module ConcreteChain (O : PrefixOracle) = {
  proc hash = O.hash
  proc derive = O.derive
  proc value(seed : raw_input, layer tree kp index stop : int) : raw_input = {
    var d, current;
    d <@ PreparationView(O).wots(wots_tail layer tree kp index);
    current <@ RawWots(PreparationView(O)).chain(seed,layer,tree,kp,index,node d,0,stop);
    return current;
  }
}.
module ChainWots (O : ChainOracle) = {
  proc count = RawWots(PreparationView(ChainPrefix(O))).count
  proc recover = RawWots(PreparationView(ChainPrefix(O))).recover
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, result, order, step, i, current, sigma;
    accepted <@ count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted <> None) {
      sigma <- nseq 43 (nseq 16 0);
      order <@ RawShuffle(PreparationView(ChainPrefix(O))).permutation(shuffle,43);
      step <- 0;
      while (step < 43) {
        i <- nth 0 order step;
        current <@ O.value(seed,layer,tree,kp,i,RadixEncoding.digit 3 (oget accepted).`2 i);
        sigma <- put sigma i current; step <- step+1;
      }
      result <- Some (sigma,(oget accepted).`1);
    }
    return result;
  }
}.

lemma chain_wots_sign_projection (O <: PrefixOracle) :
  equiv [RawWots(PreparationView(O)).sign ~ ChainWots(ConcreteChain(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob O}).
  + call (_ : ={glob O}); first by sim. auto.
  sp 1 1; if; auto.
  wp; while (={seed,layer,tree,kp,accepted,order,step,sigma,glob O}).
  + wp; inline ConcreteChain(O).value.
    wp; call (_ : ={glob O}); first by sim.
    wp; call (_ : ={glob O}); first by sim. auto.
  wp; call (_ : ={glob O}); first by sim. auto.
qed.

lemma chain_wots_recover_projection (O <: PrefixOracle) :
  equiv [RawWots(PreparationView(O)).recover ~ ChainWots(ConcreteChain(O)).recover :
    ={arg,glob O} ==> ={res,glob O}].
proof. by sim. qed.

lemma concrete_chain_value_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless ConcreteChain(O).value.
proof.
  move=> hh hd; proc; call (raw_chain_lossless (PreparationView(O)) hh).
  inline PreparationView(O).wots; wp; call hd; auto.
qed.

lemma chain_wots_sign_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless ChainWots(O).sign.
proof.
  move=> hh hv; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (raw_count_lossless (PreparationView(ChainPrefix(O))) hh); auto.
  sp 1; if; auto; wp; while true (43-step).
  + move=> z; wp; call hv; auto; smt().
  wp; call (shuffle_permutation_lossless (PreparationView(ChainPrefix(O))) hh); auto; smt().
qed.
