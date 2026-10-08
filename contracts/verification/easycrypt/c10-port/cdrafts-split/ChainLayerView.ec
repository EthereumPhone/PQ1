(* Exact layer signing through trusted chain-value requests. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawLayer RawShuffle RawWots RawMerkle.
require import ChainValueView ChainKeygenView ChainMerkleView.
module ChainLayer (O : ChainOracle) = {
  proc recover(seed : raw_input, layer tree leaf : int, message : raw_input, sig : layer_signature) : raw_input = {
    var pk, root;
    pk <@ ChainWots(O).recover(seed,layer,tree,leaf,message,sig.`1,sig.`2);
    root <@ ChainMerkle(O).recover(seed,layer,tree,pk,leaf,sig.`3);
    return root;
  }
  proc sign(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) : (layer_signature * raw_input) option = {
    var built, subseed, signed, sig, root, result;
    built <@ ChainMerkle(O).build(seed,layer,tree,leaf);
    subseed <@ RawShuffle(PreparationView(ChainPrefix(O))).derive(shuffle,layer_label layer);
    signed <@ ChainWots(O).sign(seed,layer,tree,leaf,message,subseed);
    result <- None;
    if (signed <> None) {
      sig <- ((oget signed).`1,(oget signed).`2,built.`1);
      root <@ recover(seed,layer,tree,leaf,message,sig);
      result <- Some (sig,root);
    }
    return result;
  }
}.

lemma chain_layer_recover_projection (O <: PrefixOracle) :
  equiv [RawLayer(PreparationView(O)).recover ~ ChainLayer(ConcreteChain(O)).recover :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; call (chain_merkle_recover_projection O); call (chain_wots_recover_projection O); auto.
qed.
lemma chain_layer_sign_projection (O <: PrefixOracle) :
  equiv [RawLayer(PreparationView(O)).sign ~ ChainLayer(ConcreteChain(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; sp 0 0; seq 3 3 : (={seed,layer,tree,leaf,message,signed,built,glob O}).
  + call (chain_wots_sign_projection O).
    call (_ : ={glob O}); first by sim.
    call (chain_merkle_build_projection O); auto.
  sp 1 1; if; auto; wp; call (chain_layer_recover_projection O); auto.
qed.
lemma chain_layer_recover_lossless (O <: ChainOracle) :
  islossless O.hash => islossless ChainLayer(O).recover.
proof.
  move=> hh; proc; call (merkle_recover_lossless (PreparationView(ChainPrefix(O))) hh);
    call (raw_recover_lossless (PreparationView(ChainPrefix(O))) hh); auto.
qed.
lemma chain_layer_sign_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.value => islossless ChainLayer(O).sign.
proof.
  move=> hh hv; proc; seq 3 : true 1%r 1%r 0%r 0%r => //.
  + call (chain_wots_sign_lossless O hh hv).
    call (shuffle_derive_lossless (PreparationView(ChainPrefix(O))) hh).
    call (chain_merkle_build_lossless O hh hv); auto.
  sp 1; if; auto; wp; call (chain_layer_recover_lossless O hh); auto.
qed.
