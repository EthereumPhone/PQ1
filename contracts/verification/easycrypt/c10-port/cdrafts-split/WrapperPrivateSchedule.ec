(* Delay an unused private component across the actual FORS construction.
   This is an exact memo-oracle coupling, not an assumption that hidden
   signatures may be deleted or that their status leaks no information. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors.
require import PrivateValueSampling PrivateValueContext ForsPrivateLeaves ForsSignWitness.

module type WrapperForsTree (O : PrefixOracle) = {
  proc tree(seed : raw_input, ht tree target : int) : raw_input * raw_input list { O.hash, O.derive }
}.
module WrapperConcreteForsTree (O : PrefixOracle) = {
  proc tree = RawFors(PreparationView(O)).tree
}.

lemma wrapper_private_sample_tree
  (T <: WrapperForsTree {-Independent,-PrivateMemoSample,-PrivateValueSample}) :
  eager [PrivateValueSample.sample();, T(Independent).tree ~ T(Independent).tree, PrivateValueSample.sample(); :
    ={arg,glob T,glob Independent,glob PrivateValueSample} ==>
    ={res,glob T,glob Independent,glob PrivateValueSample}].
proof.
  eager proc (={glob Independent,glob PrivateValueSample}) => //; try by sim.
  + apply private_value_sample_hash.
  apply private_value_sample_derive.
qed.

module WrapperForsScheduled = {
  proc early(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var result;
    PrivateValueSample.target <- fors_private_key ht tree target;
    PrivateValueSample.sample();
    result <@ RawFors(PreparationView(Independent)).tree(seed,ht,tree,target);
    return (node PrivateValueSample.value,result.`2,result.`1);
  }
  proc late(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var result;
    PrivateValueSample.target <- fors_private_key ht tree target;
    result <@ RawFors(PreparationView(Independent)).tree(seed,ht,tree,target);
    PrivateValueSample.sample();
    return (node PrivateValueSample.value,result.`2,result.`1);
  }
}.

lemma wrapper_fors_secret_sampling_order :
  equiv [WrapperForsScheduled.early ~ WrapperForsScheduled.late :
    ={arg,glob Independent,glob PrivateValueSample} ==>
    ={res,glob Independent,glob PrivateValueSample}].
proof.
  proc; seq 1 1 : (={seed,ht,tree,target,glob Independent,glob PrivateValueSample}); first by auto.
  eager call (wrapper_private_sample_tree WrapperConcreteForsTree); auto.
qed.

module WrapperDeferredFors = {
  proc sign(seed : raw_input, ht tree target : int) : raw_input * raw_input list * raw_input = {
    var result, sd;
    result <@ RawFors(PreparationView(Independent)).tree(seed,ht,tree,target);
    sd <@ PreparationView(Independent).fors(fors_tail ht tree target);
    return (node sd,result.`2,result.`1);
  }
}.

lemma wrapper_fors_early_projection :
  equiv [ForsSignWitness(PreparationView(Independent)).sign ~ WrapperForsScheduled.early :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; call (_ : ={glob Independent}); first by sim.
  inline PrivateValueSample.sample PrivateMemoSample.get PreparationView(Independent).fors Independent.derive.
  sp; if; auto; rewrite /fors_private_key; smt().
qed.

lemma wrapper_fors_late_projection :
  equiv [WrapperForsScheduled.late ~ WrapperDeferredFors.sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  proc; seq 2 1 : (={seed,ht,tree,target,result,glob Independent} /\
    PrivateValueSample.target{1}=fors_private_key ht{1} tree{1} target{1}).
  + call (_ : ={glob Independent}); first by sim.
    auto.
  inline PrivateValueSample.sample PrivateMemoSample.get PreparationView(Independent).fors Independent.derive.
  sp; if; auto; rewrite /fors_private_key; smt().
qed.

lemma wrapper_fors_deferred_secret :
  equiv [ForsSignWitness(PreparationView(Independent)).sign ~ WrapperDeferredFors.sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  transitivity WrapperForsScheduled.early
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + exact wrapper_fors_early_projection.
  transitivity WrapperForsScheduled.late
    (={arg,glob Independent,glob PrivateValueSample} ==> ={res,glob Independent,glob PrivateValueSample})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + exact wrapper_fors_secret_sampling_order.
  exact wrapper_fors_late_projection.
qed.
