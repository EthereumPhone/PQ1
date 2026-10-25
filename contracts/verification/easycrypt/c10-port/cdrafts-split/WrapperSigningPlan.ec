(* Internal signing plans retain public values and the accepted digest.
   Ordinary FORS nodes are represented by their stable private-table entries,
   not materialized through the opening interface. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import ForsLeafView WrapperForestMemo WrapperForestPlan WrapperLayerMemo WrapperDeferredSigner.

type wrapper_signature_plan = raw_input * digest * raw_input * raw_input list list * layer_signature list.

op wrapper_planned_signature s (signature : raw_signature) (plan : wrapper_signature_plan) =
  signature.`1=plan.`1 /\ signature.`3=plan.`4 /\ signature.`4=plan.`5 /\
  nth (nseq 16 0) signature.`2 12=plan.`3 /\
  wrapper_fors_memo_prefix s (hypertree_index plan.`2) plan.`2 signature.`2 (range 0 12).

op wrapper_planned_result s (signed : raw_signature option) (planned : wrapper_signature_plan option) =
  (signed=None)=(planned=None) /\
  (signed<>None => wrapper_planned_signature s (oget signed) (oget planned)).

module WrapperSigningPlan (O : PrefixOracle) (F : ForsLeafOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : wrapper_signature_plan option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
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
      result <- Some (randomizer,digest,forest.`1,forest.`2,layers);
    }
    return result;
  }
}.

lemma wrapper_signing_plan_finish_projection seed_ref digest_ref :
  equiv [RawSigner(Independent).finish ~
    WrapperSigningPlan(Independent,ConcreteForsLeaf(PreparationView(Independent))).finish :
    seed{1}=seed_ref /\ digest{1}=digest_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_planned_result Independent.secrethistory{1} res{1} res{2} /\
    (res{2}<>None => (oget res{2}).`2=digest_ref)].
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
  auto; rewrite /wrapper_planned_result /wrapper_planned_signature /wrapper_forest_relation;
    smt().
qed.
