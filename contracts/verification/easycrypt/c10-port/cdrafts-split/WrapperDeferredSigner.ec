(* FORS materialization occurs only after both layer signatures succeed.
   The original optional result and oracle tables are preserved, including
   the layer-failure paths. Wrapper release guards are a later boundary. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import ForsLeafView WrapperForestMemo WrapperForestPlan WrapperForestRelease WrapperLayerMemo.

op wrapper_forest_relation s ht digest
  (signed_forest : raw_input list * raw_input list list * raw_input)
  (public_plan : raw_input * raw_input list list * raw_input) =
  signed_forest.`2=public_plan.`2 /\ signed_forest.`3=public_plan.`3 /\
  nth (nseq 16 0) signed_forest.`1 12=public_plan.`1 /\
  wrapper_fors_memo_prefix s ht digest signed_forest.`1 (range 0 12).

module WrapperDeferredSigner (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : raw_signature option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result, secrets;
    ht <- hypertree_index digest;
    forest <@ WrapperForestPlan(PreparationView(O),F).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ RawLayer(PreparationView(O)).sign(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed = None) { ok <- false; } else {
        layers <- rcons layers (oget signed).`1; current <- (oget signed).`2;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) {
      secrets <@ WrapperForestRelease(F).values(ht,digest,forest.`1);
      result <- Some (randomizer,secrets,forest.`2,layers);
    }
    return result;
  }
}.

lemma wrapper_deferred_finish_projection seed_ref digest_ref :
  equiv [RawSigner(Independent).finish ~
    WrapperDeferredSigner(Independent,ConcreteForsLeaf(PreparationView(Independent))).finish :
    seed{1}=seed_ref /\ digest{1}=digest_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; seq 2 2 : (seed{1}=seed_ref /\ digest{1}=digest_ref /\ ht{1}=hypertree_index digest_ref /\
    ={seed,randomizer,digest,shuffle,ht,Independent.rawhistory,Independent.secrethistory} /\
    wrapper_forest_relation Independent.secrethistory{1} (hypertree_index digest_ref) digest_ref forest{1} forest{2}).
  + call (wrapper_forest_public_plan seed_ref (hypertree_index digest_ref) digest_ref).
    auto; rewrite /wrapper_forest_relation; smt().
  seq 6 6 : (digest{1}=digest_ref /\ ht{1}=hypertree_index digest_ref /\
    ={randomizer,digest,ht,layers,ok,Independent.rawhistory,Independent.secrethistory} /\
    wrapper_forest_relation Independent.secrethistory{1} (hypertree_index digest_ref) digest_ref forest{1} forest{2}).
  + while (digest{1}=digest_ref /\ ht{1}=hypertree_index digest_ref /\
      ={seed,randomizer,digest,shuffle,ht,current,idx_tree,layer,layers,ok,Independent.rawhistory,Independent.secrethistory} /\
      wrapper_forest_relation Independent.secrethistory{1} (hypertree_index digest_ref) digest_ref forest{1} forest{2}).
    - exists* forest{1}; elim* => forest_ref.
      wp; call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\
        wrapper_fors_memo_prefix Independent.secrethistory{1} (hypertree_index digest_ref) digest_ref forest_ref.`1 (range 0 12) ==>
        ={res,Independent.rawhistory,Independent.secrethistory} /\
        wrapper_fors_memo_prefix Independent.secrethistory{1} (hypertree_index digest_ref) digest_ref forest_ref.`1 (range 0 12)).
      * conseq (wrapper_layer_table_projection WrapperConcreteLayer)
          (wrapper_layer_keeps_fors_memo (hypertree_index digest_ref) digest_ref forest_ref.`1 (range 0 12)); smt().
      auto; rewrite /wrapper_forest_relation; smt().
    auto; rewrite /wrapper_forest_relation; smt().
  sp 1 1; if => //.
  exists* forest{1},Independent.secrethistory{2},Independent.rawhistory{2},Independent.queries{2};
    elim* => forest_ref s_ref h_ref q_ref.
  wp; call{2} (wrapper_forest_release_total (hypertree_index digest_ref) digest_ref forest_ref.`1 s_ref h_ref q_ref).
  auto; rewrite /wrapper_forest_relation; smt().
qed.
