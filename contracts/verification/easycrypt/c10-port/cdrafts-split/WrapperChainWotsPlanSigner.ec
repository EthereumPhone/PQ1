(* The complete plan uses only endpoint requests during internal WOTS work.
   Count search, shuffle, forest work and all refusal paths remain exact. *)
require import AllCore List IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind RoleGrind RoleGrindCost.
require import RawKeygen RawForest RawLayer RawSigner ChainValueView WrapperChainLayerPlan WrapperWotsSigningPlan WrapperWotsPlanSigner.
module WrapperChainWotsPlanSigner (O : ChainOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : wrapper_wots_signature_plan option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ RawForest(PreparationView(ChainPrefix(O))).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ WrapperChainLayerPlan(O).plan(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed); current <- (oget signed).`4;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,digest,forest,layers); }
    return result;
  }
  proc sign(seed root random message shuffle : raw_input) : wrapper_wots_signature_plan option = {
    var accepted, result;
    accepted <@ RoleGrind(ChainPrefix(O)).run(random,message,seed,root);
    result <- None;
    if (accepted <> None) {
      result <@ finish(seed,(oget accepted).`1,(oget accepted).`2,shuffle);
    }
    return result;
  }
}.
lemma wrapper_chain_wots_finish_projection (O <: PrefixOracle) :
  equiv [WrapperWotsSigningPlan(O).finish ~ WrapperChainWotsPlanSigner(ConcreteChain(O)).finish :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; wp; while (={seed,randomizer,digest,forest,current,idx_tree,layer,layers,ok,shuffle,glob O}).
  + wp; call (wrapper_chain_layer_plan_projection O); auto.
  wp; call (_ : ={glob O}); first by sim. auto.
qed.
lemma wrapper_chain_wots_sign_projection (O <: PrefixOracle) :
  equiv [WrapperWotsPlanSigner(O).sign ~ WrapperChainWotsPlanSigner(ConcreteChain(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob O}).
  + call (_ : ={glob O}); first by sim. auto.
  sp 1 1; if; auto; call (wrapper_chain_wots_finish_projection O); auto.
qed.
lemma wrapper_chain_wots_finish_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.derive => islossless O.value => islossless WrapperChainWotsPlanSigner(O).finish.
proof.
  move=> hh hd hv; have [#] vh vw vf := preparation_view_lossless (ChainPrefix(O)) hh hd.
  proc; wp; while true (2-layer).
  + move=> z; wp; call (wrapper_chain_layer_plan_lossless O hh hv); auto; smt().
  wp; call (forest_sign_lossless (PreparationView(ChainPrefix(O))) vh vf); auto; smt().
qed.
lemma wrapper_chain_wots_sign_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.derive => islossless O.value => islossless WrapperChainWotsPlanSigner(O).sign.
proof.
  move=> hh hd hv; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (role_grind_lossless (ChainPrefix(O)) hh hd); auto.
  sp 1; if; auto; call (wrapper_chain_wots_finish_lossless O hh hd hv); auto.
qed.
