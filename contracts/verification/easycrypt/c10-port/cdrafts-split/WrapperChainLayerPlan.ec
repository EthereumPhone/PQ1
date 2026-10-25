(* The chain-interface plan requests only builder endpoints. A proper selected
   cut remains unopened throughout this internal computation, including refusal. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle RawLayer.
require import ChainValueView ChainMerkleView ChainStageSampling CachedChainOracle ChainObserverProjection.
require import ObservedValueOpening ObservedKeygenOpening WrapperWotsPlan WrapperLayerPlan.

module WrapperChainLayerPlan (O : ChainOracle) = {
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

module type WrapperChainPlanner (O : ChainOracle) = {
  proc plan(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) :
    wrapper_layer_plan option { O.hash,O.derive,O.value }
}.

lemma wrapper_wots_plan_lossless (O <: PrefixOracle) :
  islossless O.hash => islossless WrapperWotsPlan(O).plan.
proof.
  move=> hh; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (raw_count_lossless (PreparationView(O)) hh); auto.
  if; auto; call (shuffle_permutation_lossless (PreparationView(O)) hh); auto.
qed.

lemma wrapper_chain_layer_plan_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless WrapperChainLayerPlan(O).plan.
proof.
  move=> hh hv; proc; wp; call (wrapper_wots_plan_lossless (ChainPrefix(O)) hh).
  call (shuffle_derive_lossless (PreparationView(ChainPrefix(O))) hh).
  call (chain_merkle_build_lossless O hh hv); auto.
qed.

lemma wrapper_chain_layer_plan_projection (O <: PrefixOracle) :
  equiv [WrapperLayerPlan(O).plan ~ WrapperChainLayerPlan(ConcreteChain(O)).plan :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  call (chain_merkle_build_projection O); auto.
qed.

lemma wrapper_chain_plan_observer_projection
  (P <: WrapperChainPlanner {-Independent,-ChainStage,-ChainCut,-ChainRevelation,-CachedChain,-ObservedChain}) :
  equiv [P(ConcreteChain(Independent)).plan ~ P(ObservedChain(Independent)).plan :
    ={arg,glob P,glob Independent} ==> ={res,glob P,glob Independent}].
proof.
  proc (={glob Independent}) => //.
  + by sim.
  + proc*; call observed_private_projection; auto.
  proc*; call observed_value_projection; auto.
qed.

lemma wrapper_chain_layer_plan_unopened seed0 layer0 tree0 opened0 :
  hoare [WrapperChainLayerPlan(ObservedChain(Independent)).plan :
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
