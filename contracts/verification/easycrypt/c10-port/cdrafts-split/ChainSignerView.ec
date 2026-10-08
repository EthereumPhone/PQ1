(* Exact complete-signature projection through the trusted chain-position interface. *)
require import AllCore List IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind RoleGrindCost.
require import RawKeygen RawForest RawLayer RawSigner ChainValueView ChainLayerView.
module ChainSigner (O : ChainOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ RawForest(PreparationView(ChainPrefix(O))).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ ChainLayer(O).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed).`1; current <- (oget signed).`2;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,forest.`1,forest.`2,layers); }
    return result;
  }
  proc sign(seed root random message shuffle : raw_input) : raw_signature option = {
    var accepted, result;
    accepted <@ RoleGrind(ChainPrefix(O)).run(random,message,seed,root);
    result <- None;
    if (accepted <> None) {
      result <@ finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
  proc verify = RawSigner(ChainPrefix(O)).verify
}.
lemma chain_signer_finish_projection (O <: PrefixOracle) :
  equiv [RawSigner(O).finish ~ ChainSigner(ConcreteChain(O)).finish :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; while (={seed,randomizer,forest,current,idx_tree,layer,layers,ok,shuffle,glob O}).
  + wp; call (chain_layer_sign_projection O); auto.
  wp; call (_ : ={glob O}); first by sim. auto.
qed.
lemma chain_signer_sign_projection (O <: PrefixOracle) :
  equiv [RawSigner(O).sign ~ ChainSigner(ConcreteChain(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob O}).
  + call (_ : ={glob O}); first by sim. auto.
  sp 1 1; if; auto; call (chain_signer_finish_projection O); auto.
qed.
lemma chain_signer_finish_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainSigner(O).finish.
proof.
  move=> hh hd hv; have [#] vh vw vf := preparation_view_lossless (ChainPrefix(O)) hh hd.
  proc; wp; while true (2-layer).
  + move=> z; wp; call (chain_layer_sign_lossless O hh hv); auto; smt().
  wp; call (forest_sign_lossless (PreparationView(ChainPrefix(O))) vh vf); auto; smt().
qed.
lemma chain_signer_sign_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.derive => islossless O.value => islossless ChainSigner(O).sign.
proof.
  move=> hh hd hv; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (role_grind_lossless (ChainPrefix(O)) hh hd); auto.
  sp 1; if; auto; call (chain_signer_finish_lossless O hh hd hv); auto.
qed.
