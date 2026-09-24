(* Proof observer retaining the root computed by the actual layer builder. *)
require import AllCore List.
require import C10RawOracle KeygenPrefixes RawKeygen RawShuffle RawWots RawMerkle RawLayer.

module LayerSignWitness (O : PreparationOracle) = {
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) :
      (layer_signature * raw_input) option * raw_input = {
    var built, subseed, signed, sig, root, result;
    built <@ RawMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ RawShuffle(O).derive(shuffle,layer_label layer);
    signed <@ RawWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
      root <@ RawLayer(O).recover(seed,layer,tree,leaf,message,sig);
      result <- Some (sig,root);
    }
    return (result,built.`2);
  }
}.

lemma layer_sign_witness_projection (O <: PreparationOracle) :
  equiv [RawLayer(O).sign ~ LayerSignWitness(O).sign :
    ={seed,layer,tree,leaf,message,shuffle,glob O} ==> res{1}=res{2}.`1 /\ ={glob O}].
proof.
  proc; seq 3 3 : (={seed,layer,tree,leaf,message,built,signed,glob O}).
  + call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  sp 1 1; if; auto; wp.
  call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto.
qed.
