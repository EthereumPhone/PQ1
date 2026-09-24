(* Exact oracle-effect-preserving factoring of the actual key-generation leaf. *)
require import AllCore List.
require import C10RawOracle KeygenPrefixes RawKeygen RawWots.

module RawLeafChains (O : PreparationOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input = {
    var i, d, current, elements;
    i <- 0; elements <- [];
    while (i < 43) {
      d <@ O.wots(wots_tail layer tree kp i);
      current <@ RawWots(O).chain(seed,layer,tree,kp,i,node d,0,7);
      elements <- rcons elements (pad current); i <- i+1;
    }
    d <@ O.hash(seed ++ address layer tree 1 kp 0 0 0 ++ flatten elements);
    return node d;
  }
}.

lemma raw_leaf_chain_projection (O <: PreparationOracle) :
  equiv [RawKeygen(O).leaf ~ RawLeafChains(O).leaf :
    ={seed,layer,tree,kp,glob O} ==> ={res,glob O}].
proof.
  proc; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  wp; while (={seed,layer,tree,kp,i,elements,glob O}).
  + inline RawWots(O).chain; wp.
    while (={j,glob O} /\ seed{1}=seed0{2} /\ layer{1}=layer0{2} /\
      tree{1}=tree0{2} /\ kp{1}=kp0{2} /\ i{1}=index{2} /\ stop{2}=7 /\
      current{1}=current0{2} /\ ={seed,layer,tree,kp,i,elements}).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
      auto.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  auto.
qed.
