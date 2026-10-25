(* The internal WOTS plan retains the accepted count and every shuffle query.
   Requested chain values can be materialized separately from recorded chains. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import ChainValueView WotsReference WotsSignatureValue PreparationHistory PersistentGrind AcceptedContexts.
require import WrapperWotsValues WrapperForestPlan.

module WrapperWotsPlan (O : PrefixOracle) = {
  proc fill(seed : raw_input, layer tree kp : int, accepted : digest, shuffle : raw_input) : raw_input list = {
    var order, sigma;
    order <@ RawShuffle(PreparationView(O)).permutation(shuffle,43);
    sigma <@ WrapperWotsValues(ConcreteChain(O)).run(seed,layer,tree,kp,accepted,order);
    return sigma;
  }
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (raw_input list * int) option = {
    var accepted, sigma, result;
    accepted <@ RawWots(PreparationView(O)).count(seed,layer,tree,kp,message);
    result <- None;
    if (accepted<>None) {
      sigma <@ fill(seed,layer,tree,kp,(oget accepted).`2,shuffle);
      result <- Some (sigma,(oget accepted).`1);
    }
    return result;
  }
  proc plan(seed : raw_input, layer tree kp : int, message shuffle : raw_input) : (int * digest) option = {
    var accepted, order;
    accepted <@ RawWots(PreparationView(O)).count(seed,layer,tree,kp,message);
    if (accepted<>None) {
      order <@ RawShuffle(PreparationView(O)).permutation(shuffle,43);
    }
    return accepted;
  }
}.

lemma wrapper_wots_sign_factor (O <: PrefixOracle) :
  equiv [ChainWots(ConcreteChain(O)).sign ~ WrapperWotsPlan(O).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; inline WrapperWotsPlan(O).fill WrapperWotsValues(ConcreteChain(O)).run.
  seq 1 1 : (={seed,layer,tree,kp,message,shuffle,accepted,glob O}).
  + call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  sp 1 1; if; auto; wp.
  while (seed{1}=seed1{2} /\ layer{1}=layer1{2} /\ tree{1}=tree1{2} /\ kp{1}=kp1{2} /\
    accepted1{2}=(oget accepted{1}).`2 /\ sigma{1}=sigma1{2} /\
    order{1}=order0{2} /\ ={step,accepted,glob O}).
  + wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto.
qed.

lemma wrapper_shuffle_wots_prefix seed0 layer0 tree0 kp0 :
  hoare [RawShuffle(PreparationView(Independent)).permutation :
    n=43 /\ wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 ==>
    perm_eq res (range 0 43) /\
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (raw_shuffle_recorded 43 s0 h0); smt(extends_refl wots_prefix_extends).
qed.

lemma wrapper_wots_values_guarded seed0 layer0 tree0 kp0 d0 order0 h0 s0 :
  phoare [WrapperWotsValues(ConcreteChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ order=order0 /\
    perm_eq order0 (range 0 43) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 res] = 1%r.
proof.
  case: (perm_eq order0 (range 0 43)) => hp.
  + conseq (wrapper_wots_values_total seed0 layer0 tree0 kp0 d0 order0 h0 s0 hp); smt().
  conseq (_ : false ==> true).
  conseq (wrapper_wots_values_lossless (ConcreteChain(Independent))
    (concrete_chain_value_lossless Independent independent_hash_ll independent_derive_ll)); smt().
qed.

lemma wrapper_wots_fill_plan seed_ref layer_ref tree_ref kp_ref d0 :
  equiv [WrapperWotsPlan(Independent).fill ~
    RawShuffle(PreparationView(Independent)).permutation :
    seed{1}=seed_ref /\ layer{1}=layer_ref /\ tree{1}=tree_ref /\ kp{1}=kp_ref /\ accepted{1}=d0 /\
    shuffle{1}=seed{2} /\ n{2}=43 /\
    ={Independent.rawhistory,Independent.secrethistory} /\
    wots_prefix Independent.rawhistory{1} Independent.secrethistory{1} seed_ref layer_ref tree_ref kp_ref 43 ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wots_prefix Independent.rawhistory{1} Independent.secrethistory{1} seed_ref layer_ref tree_ref kp_ref 43 /\
    wots_signature Independent.rawhistory{1} Independent.secrethistory{1} seed_ref layer_ref tree_ref kp_ref d0 res{1}].
proof.
  proc*.
  inline{1} WrapperWotsPlan(Independent).fill.
  seq 7 1 : (seed0{1}=seed_ref /\ layer0{1}=layer_ref /\ tree0{1}=tree_ref /\ kp0{1}=kp_ref /\ accepted0{1}=d0 /\
    ={Independent.rawhistory,Independent.secrethistory} /\ perm_eq order{1} (range 0 43) /\
    wots_prefix Independent.rawhistory{1} Independent.secrethistory{1} seed_ref layer_ref tree_ref kp_ref 43).
  + call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\ n{1}=43 /\
      wots_prefix Independent.rawhistory{1} Independent.secrethistory{1} seed_ref layer_ref tree_ref kp_ref 43 ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\ perm_eq res{1} (range 0 43) /\
      wots_prefix Independent.rawhistory{1} Independent.secrethistory{1} seed_ref layer_ref tree_ref kp_ref 43).
    - conseq (wrapper_shuffle_table_projection WrapperConcreteShuffle)
        (wrapper_shuffle_wots_prefix seed_ref layer_ref tree_ref kp_ref); smt().
    auto.
  exists* order{1},Independent.rawhistory{1},Independent.secrethistory{1}; elim* => ord h0 s0.
  wp; call{1} (wrapper_wots_values_guarded seed_ref layer_ref tree_ref kp_ref d0 ord h0 s0).
  auto.
qed.
