(* An observed concrete chain and its precomputed cache have the same trusted interface. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen WotsReference.
require import ChainValueView ChainStageSampling ChainCacheInvariant.

module ChainCut = { var cut : int }.
module ChainRevelation = { var opened : bool }.
module ChainObservedPrefix (O : PrefixOracle) = {
  proc hash = O.hash
  proc derive(tail : raw_input) : digest = {
    var d;
    ChainRevelation.opened <- ChainRevelation.opened \/
      tail=wots_key ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index;
    d <@ O.derive(tail); return d;
  }
}.
module ObservedChain (O : PrefixOracle) = {
  proc hash = O.hash
  proc derive = ChainObservedPrefix(O).derive
  proc value(seed : raw_input, layer tree kp index stop : int) : raw_input = {
    var result;
    if ((seed,layer,tree,kp,index)=(ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index) /\
        0<=stop<=7) {
      ChainRevelation.opened <- ChainRevelation.opened \/ stop<=ChainCut.cut;
      result <@ ConcreteChain(O).value(seed,layer,tree,kp,index,stop);
    } else {
      result <@ ConcreteChain(ChainObservedPrefix(O)).value(seed,layer,tree,kp,index,stop);
    }
    return result;
  }
}.
module CachedChain = {
  proc hash = Independent.hash
  proc derive = ChainObservedPrefix(Independent).derive
  proc value(seed : raw_input, layer tree kp index stop : int) : raw_input = {
    var result;
    if ((seed,layer,tree,kp,index)=(ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index) /\
        0<=stop<=7) {
      ChainRevelation.opened <- ChainRevelation.opened \/ stop<=ChainCut.cut;
      result <- nth (nseq 16 0) ChainStage.values stop;
    } else {
      result <@ ConcreteChain(ChainObservedPrefix(Independent)).value(seed,layer,tree,kp,index,stop);
    }
    return result;
  }
}.
module type ChainContext (O : ChainOracle) = {
  proc run() : raw_input list {O.hash,O.derive,O.value}
}.

lemma chain_observed_prefix_lossless
  (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive =>
  islossless ChainObservedPrefix(O).hash /\ islossless ChainObservedPrefix(O).derive.
proof. move=> hh hd; split; first exact hh. proc; call hd; auto. qed.

lemma observed_chain_value_lossless
  (O <: PrefixOracle) :
  islossless O.hash => islossless O.derive => islossless ObservedChain(O).value.
proof.
  move=> hh hd; have [hp dp] := chain_observed_prefix_lossless O hh hd.
  proc; if.
  + call (concrete_chain_value_lossless O hh hd); auto.
  call (concrete_chain_value_lossless (ChainObservedPrefix(O)) hp dp); auto.
qed.
lemma cached_chain_value_lossless : islossless CachedChain.value.
proof.
  have [hh hd] := chain_observed_prefix_lossless Independent independent_hash_ll independent_derive_ll.
  proc; if; auto; call (concrete_chain_value_lossless (ChainObservedPrefix(Independent)) hh hd); auto.
qed.
